:layout: compact


.. raw:: html

   <img alt="_images/logo-new-big-transparent.png" class="align-left" src="_static/logo-new-big-transparent.png" style="width: 290px; height: 290px;">
   <br>
   <br>
   <h1 class="title-gradient">Dementor</h1>

.. rst-class:: lead

   IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner - you can think if it as `Responder <https://github.com/lgandx/Responder">`_ 2.0


.. container:: buttons

    `Docs <intro.html>`_
    `GitHub <https://github.com/MatrixEditor/Dementor>`_



.. grid:: 1 1 2 3
   :gutter: 2
   :padding: 1
   :class-row: surface

   .. grid-item-card:: :octicon:`star` Attack Examples
      :link: intro.html

      Example attacks that can be carried out using *Dementor*.

   .. grid-item-card:: :octicon:`zap` Feature-rich Toolbox
      :link: config/protocols.html

      Basic implementation of common network servers including SMB, SMTP, FTP and many more.

   .. grid-item-card:: :octicon:`beaker` Highly Configurable
      :link: config/

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

.. container:: demo

   .. image:: _static/images/index-video.gif

.. toctree::
   :hidden:

   intro
   compat

.. toctree::
   :caption: Getting Started
   :hidden:

   config/index
   cli
   proto


.. toctree::
   :caption: Examples ⚙️
   :hidden:

   examples/multicast
   examples/kdc
   examples/smtp_downgrade
   examples/webdav_fallback

.. toctree::
   :caption: Configuration ⚙️
   :hidden:

   config/main
   config/database
   config/globals
   config/protocols
   config/logging
