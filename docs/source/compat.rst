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
                    <tr>
                        <td>Tree Connect</td>
                    </tr>
                    <tr>
                        <td>Logoff</td>
                    </tr>
                    <tr>
                        <td>NT4 clear-text capture</td>
                    </tr>
                    <tr>
                        <td>Multi-credential loop</td>
                    </tr>
                    <tr>
                        <td>Configurable ErrorCode</td>
                    </tr>
                    <tr>
                        <td>Configurable ServerOS</td>
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
                        <td>NTLMv1</td>
                    </tr>
                    <tr>
                        <td>NTLMv1-ESS</td>
                    </tr>
                    <tr>
                        <td>LMv2</td>
                    </tr>
                    <tr>
                        <td>NTLMv2</td>
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
                        <td>NTLMv2 threshold (≥ 48 B)</td>
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
                        <td>NTLMv1 capture (raw SMB1)</td>
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
                        <td>NTLMv2 configurable</td>
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
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i> <a href="#anon">[2]</a></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i> <a href="#ntlmv2thresh">[3]</a></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide badge-alert sd-text-danger l"></i> <a href="#avpairs">[4]</a></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide x sd-text-danger l"></i></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide triangle-alert sd-text-warning l"></i> <a href="#chalconf">[5]</a></td>
                    </tr>
                    <tr>
                        <td><i class="i-lucide checkfb sd-text-success l"></i></td>
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

    <p id="confusion">[1]: Responder cannot distinguish NTLMv1 from NTLMv1-ESS, labelling both as "NTLMv1-SSP". ESS changes the effective challenge (MD5(ServerChallenge ‖ ClientChallenge)[0:8]) and must be detected separately for correct hashcat cracking.</p>
    <p id="anon">[2]: Responder's <code>Is_Anonymous</code> branches on <code>SecBlobLen &lt; 260</code> or <code>&gt; 260</code> using hardcoded byte offsets. When <code>SecBlobLen == 260</code> exactly, neither branch executes and the function returns <code>None</code> (falsy), so the session is treated as authenticated when it is actually anonymous. Dementor checks the <code>NTLMSSP_NEGOTIATE_ANONYMOUS</code> flag and structural fields (empty UserName, NtChallengeResponse, and LmChallengeResponse) explicitly.</p>
    <p id="ntlmv2thresh">[3]: Responder's NTLMv2 detection threshold is <code>&gt; 60</code> bytes in <code>ParseSMBHash</code> and <code>&gt; 25</code> bytes in <code>ParseLMNTHash</code>. Per MS-NLMP §3.3.2, the minimum NTLMv2 NT response is 16 bytes (NTProofStr) + 32 bytes (blob header) = 48 bytes; the meaningful classification boundary is <code>&gt; 24</code>. Any NTLMv2 response between 25 and 60 bytes is misclassified as NTLMv1 and formatted with the wrong hashcat mode, producing an uncrackable hash line.</p>
    <p id="avpairs">[4]: Responder's <code>packets.py</code> swaps AV_PAIR IDs 0x0003 (<code>MsvAvDnsComputerName</code>) and 0x0004 (<code>MsvAvDnsDomainName</code>), emitting them with reversed AvIds relative to MS-NLMP §2.2.2.1. Additionally, <code>MsvAvNbDomainName</code> (0x0002) is populated from the server hostname value rather than the NetBIOS domain name. Dementor derives each AV_PAIR value independently from the configured FQDN and follows the spec ordering exactly.</p>
    <p id="chalconf">[5]: Responder supports a global fixed challenge via <code>Challenge = &lt;16 hex chars&gt;</code> in <code>Responder.conf</code> (<code>[Responder Core]</code> section). Only a 16-character hex string is accepted — ASCII notation is not supported, and there is no per-protocol or per-server override. The default (<code>Challenge = Random</code>) generates a fresh cryptographically random challenge per connection. Dementor additionally accepts ASCII and explicit-prefix formats and allows the challenge to be overridden per protocol section or per server instance.</p>
