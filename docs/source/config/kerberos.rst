.. _config_kerberos:

Kerberos
========

Section ``[Kerberos]``
----------------------

.. py:currentmodule:: Kerberos

.. py:attribute:: EncType
    :type: str | int
    :value: EncryptionTypes.rc4_hmac

    *Linked to* :attr:`kerberos.KerberosConfig.krb5_etype`

    Specifies the encryption type used by the KDC for pre-authentication.
    The available options include:

    - ``aes256_cts_hmac_sha1_96`` (hashcat mode ``19900``):
        AES-256 encryption CTS mode and HMAC-SHA1.

        .. warning::
            This option is incompatible with :attr:`Kerberos.Salt`. For further details, see Hashcat Issue `#2783 <https://github.com/hashcat/hashcat/issues/2783>`_ "Kerberos 5, etype 18, Pre-Auth (19900) with salt".

    - ``rc4_hmac`` (**default**, hashcat mode ``7500``):
        RC4 encryption with HMAC integrity protection.

.. py:attribute:: Salt
    :type: str

    *Linked to* :attr:`kerberos.KerberosConfig.krb5_salt`

    The Salt parameter is commented out in the configuration file. It typically defines a custom salt value for key derivation, though its use is discouraged.
    **Custom salt values should not be defined unless absolutely necessary.**

    .. note::

        By default, the salt is derived as follows:

        - For computers:
            The salt is the uppercase FQDN, followed by the hardcoded ``host`` text, and the lowercase FQDN hostname without the trailing ``$``.
            For example, with ``computer$`` in the ``CONTOSO.LOCAL`` domain, the salt would be ``CONTOSO.LOCALhostcomputer.contoso.local``.

        - For users:
            The salt consists of the uppercase FQDN and the case-sensitive username. For example, for user ``droid`` in the ``CONTOSO.LOCAL`` domain, the salt would be ``CONTOSO.LOCALdroid``.

.. py:attribute:: ErrorCode
    :type: int | str
    :value: ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN

    *Linked to* :attr:`kerberos.KerberosConfig.krb5_error_code`

    Specifies the error code to return upon successful capture of pre-authentication data. This can either be an integer value or a string describing a property in impacket's :code:`ErrorCodes`.

    .. important::

        Avoid setting this value to ``KDC_ERR_PREAUTH_REQUIRED``, as it may cause errors during processing.


Python Config
-------------

.. py:class:: kerberos.KerberosConfig

    .. py:attribute:: krb5_salt
        :type: bytes
        :value: b""

        *Corresponds to* :attr:`Kerberos.Salt`

        Although the configuration file can specify the salt as a string, it will be automatically converted to bytes.

    .. py:attribute:: krb5_error_code
        :type: int | str
        :value: ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN

        *Corresponds to* :attr:`Kerberos.ErrorCode`

    .. py:attribute:: krb5_etype
        :type: int | str
        :value: EncryptionTypes.rc4_hmac

        *Corresponds to* :attr:`Kerberos.EncType`


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: Kerberos configuration section (default values)

    [Kerberos]
    # See Hashcat Issue #2783
    # - Kerberos 5, etype 18, Pre-Auth (19900) with salt fails
    #   You can use this setting but make sure no custom salt
    #   has been configured
    EncType = "aes256_cts_hmac_sha1_96"