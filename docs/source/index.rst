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
:layout: landing

Dementor
========

.. rst-class:: lead

   IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner - you can think if it as `Responder <https://github.com/lgandx/Responder">`_ 2.0


.. container:: buttons

    `Docs </intro.html>`_
    `GitHub <https://github.com/MatrixEditor/Dementor>`_


.. grid:: 1 1 2 3
   :gutter: 2
   :padding: 1
   :class-row: surface

   .. grid-item-card:: :octicon:`star` Attack Examples

      Examples of attacks that can be performed using this tool.

   .. grid-item-card:: :octicon:`zap` Feature-rich Toolbox

      Basic implementation of common network servers including SMB, SMTP, FTP and many more.

   .. grid-item-card:: :octicon:`beaker` Highly Configurable
      :link: /config/

      Configuration can be changed for each service individually



-----


Getting Started
---------------

You can simply install Dementor using ``pip`` or directly from source!

.. code-block:: bash

   pip install dementor


A simple Example
----------------

It is recommended to run *Dementor* as ``sudo``, but it **will not be enforced**:

.. code-block:: bash

   Dementor -I eth0


.. toctree::
   :hidden:

   intro

.. toctree::
   :caption: Getting Started
   :hidden:

   config/index


.. toctree::
   :caption: Examples ⚙️
   :hidden:

   examples/multicast
   examples/kdc

.. toctree::
   :caption: Configuration ⚙️
   :hidden:

   config/protocols

.. toctree::
   :caption: API Reference ⚙️
   :hidden: