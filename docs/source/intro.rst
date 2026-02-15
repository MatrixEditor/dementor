.. _intro:

Introduction
============

`Responder <https://github.com/lgandx/Responder>`_ has been around for years, constantly evolving. Although it implements most common protocols found in Windows
environments, it's not particularly easy to extend or customize. *Dementor* aims to solve these limitations by avoiding hardcoded packets and offering extensive
configuration capabilities, all of which are detailed in the :ref:`config_idx` section.


Benefits at a glance:

- No reliance on hardcoded or precomputed packets (e.g., mDNS name parsing often fails in Responder due to static definitions)
- Fine-grained, per-protocol configuration using a modular system  (see :ref:`config_idx`)
- Near-complete protocol parity with Responder (see :ref:`compat`)
- Easy integration of new protocols via the extension system (see :ref:`custom_protocols`)

Installation
------------

The *Dementor* package can be installed either via ``pip`` from `PyPI <https://pypi.org/project/dementor/>`_
or directly from the `GitHub repository <https://github.com/MatrixEditor/dementor>`_.

.. tab-set::

    .. tab-item:: pip

        .. code-block:: bash

            pip install dementor

    .. tab-item:: pip via git

        .. code-block:: bash

            pip install git+https://github.com/MatrixEditor/dementor


CLI Usage
---------

After installation, you can start *Dementor* directly from the command line. By default, all poisoners and
protocol servers are enabled. To perform any poisoning attacks, a network interface must be explicitly specified.

For a complete list of CLI options, refer to the :ref:`cli` section.

.. code-block:: bash

    Dementor -I "$INTERFACE_NAME"


Next Steps
----------

.. grid:: 1 1 2 3
    :gutter: 2
    :padding: 0
    :class-row: surface

    .. grid-item-card:: :octicon:`star` Examples
        :link: examples/multicast.html

        Examples of attacks that can be performed using this tool.

    .. grid-item-card:: :octicon:`beaker` Configuration
        :link: config/index.html

        Detailed breakdown of configuration options for each server and protocol.

    .. grid-item-card:: :octicon:`arrow-both` Compatibility
        :link: compat.html

        Comparison between supported features in Responder and *Dementor*.