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
        <li><i class="i-lucide cancelled sd-text-secondary xl"></i> - Won't be supported. Please file a pull request explaining why this feature is necessary.</li>
    </ul>


.. raw:: html

    <table>
    <thead>
        <tr>
            <th>Supported Protocols</th>
            <th><a href="https://github.com/lgandx/Responder">Responder (3.2.2.0)</a></th>
            <th><a href="https://github.com/MatrixEditor/Dementor">Dementor (1.0.0.dev18)</a></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>DHCP</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide cancelled sd-text-secondary l"></i> (use <a class="reference external" target="_blank" href="https://www.bettercap.org/">bettercap</a>)</td>
        </tr>
        <tr>
            <td>DNS</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide cancelled sd-text-secondary l"></i> (use <a class="reference external" target="_blank" href="https://www.bettercap.org/">bettercap</a>)</td>
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
            <td><a href="./config/ssdp.html">SSDP</a></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/mssql.html">SSRP</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/quic.html">QUIC</a></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>
                <a href="./config/smb.html">SMB</a>
                <table>
                <tbody>
                    <tr>
                        <td>SMB 1.0 SSP</td>
                    </tr>
                    <tr>
                        <td>SMB 1.0 Raw</td>
                    </tr>
                    <tr>
                        <td>SMB 2.002</td>
                    </tr>
                    <tr>
                        <td>SMB 2.1</td>
                    </tr>
                    <tr>
                        <td>SMB 2.???</td>
                    </tr>
                    <tr>
                        <td>SMB 3.0</td>
                    </tr>
                    <tr>
                        <td>SMB 3.0.2</td>
                    </tr>
                    <tr>
                        <td>SMB 3.1.1</td>
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
            <td>
                NTLM
                <table>
                <tbody>
                    <tr>
                        <td>NetNTLMv1</td>
                    </tr>
                    <tr>
                        <td>NetNTLMv1-ESS</td>
                    </tr>
                    <tr>
                        <td>NetLMv2</td>
                    </tr>
                    <tr>
                        <td>NetNTLMv2</td>
                    </tr>
                    <tr>
                        <td>Dummy LM filtering</td>
                    </tr>
                    <tr>
                        <td>LM dedup filtering</td>
                    </tr>
                    <tr>
                        <td>Anonymous detection</td>
                    </tr>
                    <tr>
                        <td>Flag mirroring</td>
                    </tr>
                    <tr>
                        <td>NetNTLMv2 threshold (≥ 48 B)</td>
                    </tr>
                    <tr>
                        <td>AV_PAIRS correctness</td>
                    </tr>
                    <tr>
                        <td>Hash label accuracy</td>
                    </tr>
                    <tr>
                        <td>Configurable challenge</td>
                    </tr>
                    <tr>
                        <td>SPNEGO unwrapping</td>
                    </tr>
                    <tr>
                        <td>Non-NTLM mech redirect</td>
                    </tr>
                    <tr>
                        <td>ESS configurable</td>
                    </tr>
                    <tr>
                        <td>NetNTLMv2 configurable</td>
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
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i> <a href="#confusion">[1]</a></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
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
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
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
                        <td>NTLM</td>
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
            <td>SNMP</td>
            <td><i class="i-lucide badge-alert sd-text-danger l"></i></td>
            <td><i class="i-lucide message-square-warning sd-text-info l"></i></td>
        </tr>
        <tr>
            <td>RDP</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide cancelled sd-text-secondary l"></i> (use <a class="reference external" target="_blank" href="https://github.com/GoSecure/pyrdp">pyrdp-mitm</a>)</td>
        </tr>
        <tr>
            <td>HTTP_PROXY</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide cancelled sd-text-secondary l"></i> (use <a class="reference external" target="_blank" href="https://mitmproxy.org/">mitmproxy</a>)</td>
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
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i> <a href="#confusion">[1]</a></td>
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
            <td>
                <a href="./config/imap.html">IMAP</a>
                <table>
                <tbody>
                    <tr>
                        <td>PLAIN</td>
                    </tr>
                    <tr>
                        <td>LOGIN</td>
                    </tr>
                    <tr>
                        <td>NTLM</td>
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
            <td>
                <a href="./config/pop3.html">POP3</a>
                <table>
                <tbody>
                    <tr>
                        <td>USER/PASS</td>
                    </tr>
                    <tr>
                        <td>PLAIN</td>
                    </tr>
                    <tr>
                        <td>LOGIN</td>
                    </tr>
                    <tr>
                        <td>NTLM</td>
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
                </tbody>
                </table>
            </td>
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
            <td>
                <a href="./config/mssql.html">MSSQL</a>
                <table>
                <tbody>
                    <tr>
                        <td>Cleartext</td>
                    </tr>
                    <tr>
                        <td>NTLM</td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide triangle-alert sd-text-warning l"></i>
                <table>
                <tbody>
                    <tr>
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i> <a href="#confusion">[1]</a></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
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
                </tbody>
                </table>
            </td>
        </tr>
        <tr>
            <td>
                <a href="./config/mysql.html">MySQL</a>
                <table>
                <tbody>
                    <tr>
                        <td><code>mysql_clear_password</code></td>
                    </tr>
                    <tr>
                        <td>NTLM</td>
                    </tr>
                    <tr>
                        <td>SPNEGO</td>
                    </tr>
                </tbody>
                </table>
            </td>
            <td>
                <i class="i-lucide x sd-text-danger l"></i>
                <table>
                <tbody>
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
        </tr>
        <tr>
            <td>WinRM</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>
                <a href="./config/dcerpc.html">DCE/RPC</a>
                <table>
                <tbody>
                    <tr>
                        <td>NTLM</td>
                    </tr>
                    <tr>
                        <td>DCOM <i>(interface)</i></td>
                    </tr>
                    <tr>
                        <td>EPMv4 <i>(interface)</i></td>
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
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i></td>
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
            <td><a href="./config/x11.html">X11</a></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/ipp.html">IPP</a></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td><a href="./config/upnp.html">UPnP</a></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
    </tbody>
    </table>

    <h3>SMB Features</h3>
    <table>
    <thead>
        <tr>
            <th>Feature</th>
            <th><a href="https://github.com/lgandx/Responder">Responder (3.2.2.0)</a></th>
            <th><a href="https://github.com/MatrixEditor/Dementor">Dementor (1.0.0.dev18)</a></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Tree Connect</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>Logoff</td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>NT4 clear-text capture</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>Multi-credential loop</td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
        </tr>
        <tr>
            <td>Configurable ErrorCode</td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
        <tr>
            <td>Configurable ServerOS</td>
            <td><i class="i-lucide x sd-text-danger l"></i></td>
            <td><i class="i-lucide checkfb sd-text-success l"></i></td>
        </tr>
    </tbody>
    </table>

    <p id="confusion">[1]: Responder combines NetNTLMv1 and NetNTLMv1-ESS under a single "NTLMv1-SSP" label. This is not incorrect — hashcat <code>-m 5500</code> handles both — but Dementor distinguishes them for more granular reporting. Applies to all NTLM-capable protocols (SMB, HTTP, MSSQL, LDAP, DCE/RPC).</p>
