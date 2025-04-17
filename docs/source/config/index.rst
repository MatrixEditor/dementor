
.. _config_idx:

Configuration
=============

Configuration can be tedious—but it's also one of the most important aspects, and
good documentation makes all the difference. The sections listed below provide
detailed explanations for each configuration area.

Before diving into configuring *Dementor*, it's essential to understand the structure
of the configuration file. The configuration is written using the `TOML <https://toml.io/en/>`_
format. Make sure you're familiar with TOML's syntax and concepts to effectively work
with *Dementor*.


.. grid:: 1 1 2 2
    :gutter: 2
    :padding: 0
    :class-row: surface

    .. grid-item-card:: :octicon:`browser` Main Section
        :link: main.html

        Learn how to enable or disable specific protocol services.

    .. grid-item-card:: :octicon:`cache` Database
        :link: database.html

        Covers configuration options for credential storage and database location.

    .. grid-item-card:: :octicon:`code-square` Globals
        :link: globals.html

        Define settings that apply across multiple services or protocols.

    .. grid-item-card:: :octicon:`project-roadmap` Protocols
        :link: protocols.html

        Customize behavior for each protocol-specific service.

    .. grid-item-card:: :octicon:`file-added` Logging
        :link: logging.html

        Adjust logging behavior and debug output for *Dementor*.



.. hint::
    Need an example configuration file? No problem, its available on GitHub: `Dementor.conf <https://github.com/MatrixEditor/Dementor/blob/master/dementor/assets/Dementor.toml>`_