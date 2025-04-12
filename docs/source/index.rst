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

   .. grid-item-card:: :octicon:`star` Attack Explanations

      Detailed explanations of each attack with examples

   .. grid-item-card:: :octicon:`zap` Feature-rich Toolbox

      Basic implementation of common network servers including SMB, SMTP, FTP and many more.

   .. grid-item-card:: :octicon:`beaker` Highly Configurable

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

.. toctree::
   :caption: Configuration ⚙️
   :hidden:

   config/protocols

.. toctree::
   :caption: API Reference ⚙️
   :hidden: