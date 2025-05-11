.. _config_upnp:

UPnP
====

Section ``[UPnP]``
------------------

.. versionadded:: 1.0.0.dev11

.. py:currentmodule:: UPnP

.. py:attribute:: Port
    :type: int
    :value: 50001

    *Linked to* :attr:`upnp.UPNPConfig.upnp_port`

    Specifies the port used by the UPNP server instance.

.. py:attribute:: UUID
    :type: str

    *Linked to* :attr:`upnp.UPNPConfig.upnp_uuid`

    Specifies the device UUID to use for this UPnP device. If not set, a random UUID at startup
    will be used.

.. py:attribute:: TemplatesPath
    :type: List[str]

    *Linked to* :attr:`upnp.UPNPConfig.upnp_templates_path`

    A list of directories that store extra UPnP profiles to be used by the web server. Note that
    only the target directory specified in :attr:`UPnP.Template` will be used.

.. py:attribute:: Template
    :type: str
    :value: "upnp-default"

    *Linked to* :attr:`upnp.UPNPConfig.upnp_template`

    The directory name under one of the template directories specified in :attr:`UPnP.TemplatesPath`
    that stores the device description, service description and presentation HTML.

Device Configuration
^^^^^^^^^^^^^^^^^^^^

All template files specified here are using the templating language specified by Jinja2. By default,
the current UUID (``uuid``), the UPnP configuration (``config``), current session configuration (``session``)
and a factory method for random values (``random``) are accessible within the template.

.. py:attribute:: DDUri
    :type: str
    :value: "/dd.xml"

    *Linked to* :attr:`upnp.UPNPConfig.upnp_dd_path`

    Defines the URI and path to the local device description template. By default, the device description
    is expected to be found in ``dd.xml`` within the template directory.

    The default template corresponds to:

    .. container:: demo

        .. code-block:: xml

            <?xml version="1.0"?>
            <root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337">
                <specVersion>
                    <major>1</major>
                    <minor>0</minor>
                </specVersion>
                <device>
                    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
                    <friendlyName>Dementor</friendlyName>
                    <manufacturer>Manufacturer</manufacturer>
                    <manufacturerURL>http://{{session.ipv4}}/manufacturer/</manufacturerURL>
                    <modelDescription>user-friendly computer</modelDescription>
                    <modelName>Office Computer</modelName>
                    <modelNumber>COM{{ random(5) }}</modelNumber>
                    <modelURL>http://{{session.ipv4}}/model</modelURL>
                    <serialNumber>{{ random(10) }}</serialNumber>
                    <UDN>uuid:{{uuid}}</UDN>
                    <UPC>00000000000</UPC>
                    <serviceList>
                        <service>
                            <serviceType>urn:schemas-upnp-org:service:Dummy:1</serviceType>
                            <serviceId>urn:upnp-org:serviceId:Dummy</serviceId>
                            <SCPDURL>/{{uuid}}/{{config.upnp_scpd_path}}</SCPDURL>
                            <controlURL>/{{uuid}}/{{config.upnp_scpd_path}}</controlURL>
                            <eventSubURL>/{{uuid}}/{{config.upnp_scpd_path}}</eventSubURL>
                        </service>
                    </serviceList>
                    <deviceList>
                    </deviceList>
                    <presentationURL>http://{{session.ipv4}}:{{config.upnp_port}}/present.html</presentationURL>
                </device>
            </root>

.. py:attribute:: SCPDUri
    :type: str
    :value: "/scpd.xml"

    *Linked to* :attr:`upnp.UPNPConfig.upnp_scpd_path`

    Defines the URI and path to the local service control description template. By default, the service description
    is expected to be found in ``scpd.xml`` within the template directory.

.. py:attribute:: PresentationUri
    :type: str
    :value: "/present.html"

    *Linked to* :attr:`upnp.UPNPConfig.upnp_present_path`

    Defines the URI and path to the presentation page template.

Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: UPnP configuration section (default values)

    [UPnP]
    Port = 50001
    Template = "upnp-default"
    DDUri = "/dd.xml"
    SCPDUri = "/scpd.xml"
    PresentationUri = "/present.html"
