.. _compat:

Compatibility
=============

The following table lists the compatibility between `Responder <https://github.com/lgandx/Responder>`_ and
`Dementor <https://github.com/MatrixEditor/Dementor>`_, which protocols are available and which are currently
in development. The legend for each symbol is as follows:

.. raw:: html

    <ul>
        <li><i class="i-lucide checkfb sd-text-success xl"></i> - Supported / Working</li>
        <li><i class="i-lucide check-check sd-text-success xl"></i> - All features of this category are supported / working</li>
        <li><i class="i-lucide badge-alert sd-text-danger xl"></i> - This feature is currently broken / does not work properly</li>
        <li><i class="i-lucide x sd-text-danger xl"></i> - Not Supported / Not Implemented</li>
        <li><i class="i-lucide triangle-alert sd-text-warning xl"></i> - Partially Supported</li>
        <li><i class="i-lucide message-square-warning sd-text-info xl"></i> - In Development</li>
    </ul>


.. raw:: html

    <table>
    <thead>
        <tr>
            <th>Supported Protocols</th>
            <th><a href="https://github.com/lgandx/Responder">Responder</a></th>
            <th><a href="https://github.com/MatrixEditor/Dementor">Dementor</a></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>DHCP</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>DNS</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/netbios.html">NBTNS</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>NBTDS</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/llmnr.html">LLMNR</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/mdns.html">MDNS</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/quic.html">QUIC</a></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>
                <a href="./config/smb.html">SMB</a>
                <table>
                <tbody>
                    <tr>
                        <td>LM</td>
                    </tr>
                    <tr>
                        <td>NTLMv1</td>
                    </tr>
                    <tr>
                        <td>NTLMv2</td>
                    </tr>
                    <tr>
                        <td>NTLMv1-SSP</td>
                    </tr>
                    <tr>
                        <td>NTLMv2-SSP</td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide check-check sd-text-success l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide triangle-alert sd-text-warning l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
        </tr>
        <tr>
            <td>
                <a href="./config/kerberos.html">Kerberos KDC</a>
                <table>
                <tbody>
                    <tr>
                        <td><code>rc4_hmac</code></td>
                    </tr>
                    <tr>
                        <td><code>aes256_cts_hmac_sha1_96</code></td>
                    </tr>
                    <tr>
                        <td><code>aes128_cts_hmac_sha1_96</code></td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide triangle-alert sd-text-warning l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide check-check sd-text-success l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
        </tr>
        <tr>
            <td><a href="./config/ftp.html">FTP</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>
                <a href="./config/smtp.html">SMTP</a>
                <table>
                <tbody>
                    <tr>
                        <td>PLAIN</td>
                    </tr>
                    <tr>
                        <td>LOGIN</td>
                    </tr>
                    <tr>
                        <td>NTLMv1</td>
                    </tr>
                    <tr>
                        <td>NTLMv2</td>
                    </tr>
                    <tr>
                        <td>NTLMv1-SSP</td>
                    </tr>
                    <tr>
                        <td>NTLMv2-SSP</td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide triangle-alert sd-text-warning l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide check-check sd-text-success l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
        </tr>
        <tr>
            <td>SNMP</td>
            <td><i class="i-lucide badge-alert sd-text-danger l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>HTTP_PROXY</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>
                <a href="./config/http.html">HTTP</a>
                <table>
                <tbody>
                    <tr>
                        <td>Basic</td>
                    </tr>
                    <tr>
                        <td>NTLM</td>
                    </tr>
                    <tr>
                        <td>Bearer</td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide triangle-alert sd-text-warning l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide check-check sd-text-success l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
                    </tr>
                </tbody>
                </table>
            </td>
        </tr>
        </tr>
        <tr>
            <td>IMAP</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>POP3</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/ldap.html">LDAP</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>MQTT</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>MSSQL</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>WinRM</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>RPC</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide message-square-warning sd-text-info l"></i></td>
        </tr>
    </tbody>
    </table>