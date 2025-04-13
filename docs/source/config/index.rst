.. Copyright (c) 2025-Present MatrixEditor
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
.. _config_idx:

Configuration ⚙️
================

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