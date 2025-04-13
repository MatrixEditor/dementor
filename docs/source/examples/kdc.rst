.. Copyright (c) 2025 MatrixEditor
..
.. Permission is hereby granted, free of charge, to any person obtaining a copy
.. of this software and associated documentation files (the "Software"), to deal
.. in the Software without restriction, including without limitation the rights
.. to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
.. copies of the Software, and to permit persons to whom the Software is
.. furnished to do so, subject to the following conditions:
..
.. The above copyright notice and this permission notice shall be included in all
.. copies or substantial portions of the Software.
..
.. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
.. IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
.. FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
.. AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
.. LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
.. OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
.. SOFTWARE.
.. _example_kerberos:

Rogue Kerberos  KDC ⚙️
===========================================

*Kerberos Spec* :bdg-secondary-line:`RFC-4120`

`Kerberos <https://tools.ietf.org/html/rfc4120>`_ is a network authentication protocol designed to provide
secure identity verification using secret-key cryptography. It is the preferred authentication protocol
in Active Directory environments for domain accounts and is incompatible with workgroups. Unlike NTLM,
which uses challenge-response authentication, Kerberos utilizes a ticket-based system, mitigating the
risk of credential relay attacks (however still possible).

How it Works
------------

Kerberos follows a three-party authentication model, involving:

- A **Client** (either a user or service) that seeks authentication.
- A **Key Distribution Center (KDC)** that validates the identity and issues tickets.
- A **Service** that the client wants to access, requiring authentication.

When a user attempts to access a service, the Kerberos authentication process ensures that credentials are
exchanged securely without exposing passwords over the network.

.. figure:: /_static/images/kerberos-flow_dark.png
    :align: center

    Kerberos protocol flow

1. The client requests a Ticket Granting Ticket (TGT) from the Authentication Server (AS) within the Key Distribution Center (KDC) by sending an `AS-REQ <https://tools.ietf.org/html/rfc4120#section-5.4.1>`_ message. This request may include a timestamp encrypted with the user's Kerberos key, a process known as `Preauthentication <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961961(v=technet.10)?redirectedfrom=MSDN>`_.

2. The AS verifies the timestamp (if present) and responds with an `AS-REP <https://tools.ietf.org/html/rfc4120#section-5.4.2>`_ message. This response contains two encrypted parts: a TGT encrypted with the KDC’s key and client-specific data encrypted with the client’s key. Key information, such as the session key, is embedded in both parts to ensure shared access between the client and the KDC.

3. When the client attempts to access a service, it negotiates the authentication protocol using SPNEGO. If Kerberos is chosen, the client must obtain a Service Ticket (ST) for the target service.

4. The client sends a `TGS-REQ <https://tools.ietf.org/html/rfc4120#section-5.4.1>`_ message to the KDC requesting the ST. This message includes the TGT, the Service Principal Name ([SPN](#service-principal-name-spn)) of the target service, and additional encrypted data (such as the client’s username and timestamp) to verify authenticity.

5. The KDC decrypts the TGT using its key, extracts the session key, and verifies the client’s username. Upon validation, the KDC issues a `TGS-REP <https://tools.ietf.org/html/rfc4120#section-5.4.2>`_ message containing two encrypted sections: an ST encrypted with the service’s key and client-related data encrypted with the session key. Shared data, such as the service session key, is embedded in both sections to facilitate communication between the client and the service.

6. The client forwards the ST to the service within an `AP-REQ <https://tools.ietf.org/html/rfc4120#section-5.5.1>`_ message, which is encapsulated in the application protocol. The service decrypts the ST, retrieves the session key, and accesses the Privilege Attribute Certificate (PAC), which contains security information about the client.

7. (Optional) If the service needs to validate the PAC, it can use the Netlogon protocol to request the domain controller (DC) to `verify the PAC <https://learn.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation>`_ signature through a `KERB_VERIFY_PAC_REQUEST <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/b27be921-39b3-4dff-af4a-b7b74deb33b5>`_.

8. (Optional) The domain controller verifies the PAC and responds with a code indicating whether the PAC is valid.

9. (Optional) If mutual authentication is required, the service must authenticate itself to the client. This is done by responding to the AP-REQ message with an `AP-REP <https://tools.ietf.org/html/rfc4120#section-5.5.2>`_ message, proving its identity by encrypting a response with the session key. This ensures the service is legitimate and not a malicious impersonator.


AS-REQ Roasting via Rogue Key Distribution Center (KDC)
-------------------------------------------------------

A rogue KDC is an attacker-controlled KDC that impersonates the legitimate KDC, manipulating the Kerberos authentication process. *Dementor* offers configuration options to start a KDC service on port `88` (both TCP and UDP).

.. figure:: /_static/images/asreqroast-kdc_dark.png
    :align: center

    AS-REQ roasting flow using a rogue KDC

1. (step 3. from earlier): When the client attempts to access a service, it first negotiates the authentication protocol using SPNEGO. If Kerberos is selected, the client must obtain a Service Ticket (ST) for the target service.

2. The client sends an `AS-REQ <https://tools.ietf.org/html/rfc4120#section-5.4.1>`_ message, which includes a pre-authentication timestamp encrypted with their Kerberos key.

*Dementor* can generate hashes from that timestamp, which can be cracked using `hashcat <https://hashcat.net/hashcat/>`_. For example, the following hash was generated using the `Encryption Type <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos>`_
``23``, which points to ``RC4_HMAC_MD5`` (Hashcat mode ``7500``). It can be enabled using the :attr:`Kerberos.EncType` attribute.


.. container:: demo

    .. code-block:: console

        $ sudo Dementor -I <IFACE>
        [...]
        Kerberos   192.168.56.1  88     [+] Captured KRB5-PA Hash for droid/CONTOSO.LOCAL from 192.168.56.1:
        Kerberos   192.168.56.1  88     KRB5-PA Username: droid
        Kerberos   192.168.56.1  88     KRB5-PA Hash: $krb5pa$23$droid$CONTOSO.LOCAL$434f4e544f534f2e4c4f43414c64726f6964$f5b47b6b69f11c6eca9e494c6ba3512456c52bd2bf3dcd9fb6b381a34cf571d94c61e3c459adcae50f5f98b0c65be7951ddd3eb4
        [...]
