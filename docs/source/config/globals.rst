
.. _config_globals:


Globals
=======

The ``[Globals]`` section allows defining settings that are applied across all
protocols — given the protocol supports global overrides. Some protocol-specific
options may be limited to local scope. When available, options that support this
section include a reference to it in their documentation. This section covers
common configuration values, that can be shared across multiple services.

Filter Expressions
------------------

Target filters may be specified in several forms. These filters determine which
incoming requests should receive a response and can be written as:

- A basic string (e.g., ``"127.0.0.1"``)
- A regular expression string (e.g., ``"re:.*\._tcp\..*"``)
- A glob-style pattern (e.g., ``"g:*._mcc.*"``)
- A dictionary-based filter object (for advanced control)

The supported forms are described below.

- Basic String:
    A straightforward expression containing a target IP, hostname, or service name.

    .. container:: demo

        .. code-block:: toml
            :caption: Basic whitelist responding only to requests from 127.0.0.1

            Targets = [ "127.0.0.1" ]

- Regex-String:
    Use the ``re:`` prefix to define a Python-style regular expression.

    .. container:: demo

        .. code-block:: toml
            :caption: Responds only to service names starting with "_tcp"

            Targets = [ "re:^_tcp.*" ]

- Glob-String:
    Use Unix-style wildcard expressions by prefixing the string with ``g:``.

    .. container:: demo

        .. code-block:: toml
            :caption: Responds only to services containing "_mcc"

            Targets = [ "g:*._mcc.*" ]

    .. important::
        Glob-style filters require Python 3.13 or newer.

Advanced filtering can be done using dictionary-based filter objects:

.. py:currentmodule:: Filter

.. py:attribute:: Target
    :type: _FilterExpr

    The target filter expression, using one of the formats described above.

.. py:attribute:: File
    :type: str

    Allows loading filter expressions from an external file instead of specifying them inline.

.. hint::
    Filter objects may include custom metadata — referred to as *extras* — which are passed to the final
    :class:`~dementor.filters.FilterObj`. While currently unused, these extras may enable specialized
    handling for specific targets in future versions.

    .. container:: demo

        .. code-block:: toml
            :caption: Using extras in a filter object

            Targets = [
                { Target = "127.0.0.1", TTL = 340 }
            ]


.. py:currentmodule:: Globals

The Whitelist
-------------

All poisoners support target filtering via whitelist expressions.

.. py:attribute:: Targets
    :type: list[_FilterExprOrType]

    *Maps to* ``targets`` *internally.*

    .. versionchanged:: 1.0.0.dev16
        Renamed from `AnswerTo`

    Defines a whitelist of targets eligible for poisoning. Each item can be a basic string,
    regex, glob, or dictionary-based filter object.

    .. warning::
        Use caution when specifying global target filters, as they apply to all poisoners
        and may lead to unintended behavior.

The Blacklist
-------------

Alternatively, a blacklist can be defined to exclude certain targets.

.. py:attribute:: Ignore
    :type: list[_FilterExprOrType]

    *Maps to* ``ignored`` *internally.*

    Defines a list of targets to be ignored for poisoning. This behaves as a global
    exclusion list. Filtering behavior is identical to that described in the whitelist section.


TLS Options
-----------

.. py:attribute:: Cert
    :type: str

    Specifies the path to the certificate used when TLS is enabled.


.. py:attribute:: Key
    :type: str

    Specifies the private key file corresponding to the certificate used for TLS.