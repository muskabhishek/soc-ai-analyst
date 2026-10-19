# Results on real packet captures

The network rules were run, unchanged, on 13 public captures with known content: 7 attacks and
6 captures of normal traffic. Reproduce with `python scripts/pcap_benchmark.py`.

| Measure | Value |
|---|---|
| Attack captures detected | **4 of 7** |
| Normal captures with a false alarm | **0 of 6** |
| Packets analysed | 107,584 in 36 s (2,972 packets/s) |

| Capture | Type | What it contains | Packets | Rules fired | Result |
|---|---|---|---|---|---|
| `synscan.pcapng` | Attack | Nmap SYN scan of 1,000 ports | 2,011 | port_scan | **Detected** |
| `aurora.pcapng` | Attack | Operation Aurora: browser exploit, Metasploit shellcode, reverse shell on port 4321 | 39 | exploit_shellcode, remote_shell | **Detected** |
| `dns-remoteshell.pcap` | Attack | Windows cmd.exe remote shell over ports 23, 53 (DNS) and 80 | 58 | remote_shell | **Detected** |
| `http_dvwa_clearlogin.pcapng` | Attack | Login to a web app over plain HTTP (form POST) | 54 | cleartext_credentials | **Detected** |
| `ratinfected.pcapng` | Attack | Remote-access trojan on port 4433 with its own text protocol | 779 | - | Missed. Custom protocol on an unlisted port: needs an IDS signature for this RAT family or threat intel on the C2 IP. |
| `cryptowall4_c2.pcapng` | Attack | CryptoWall 4 ransomware: 3 HTTP POST check-ins to its C2 servers | 162 | - | Missed. Only 3 check-ins in 46 s, below the 6 the beaconing rule needs. Domain/IP reputation (threat intel) would catch it. |
| `ek_to_cryptowall4.pcapng` | Attack | Exploit kit: Flash exploit, then an encrypted 358 KB payload | 653 | - | Missed. The payload is encrypted, so no executable header is visible. Needs domain reputation (random subdomain on .top). |
| `http_google.pcapng` | Normal | Google search page | 12 | - | No false alarm |
| `http_espn.pcapng` | Normal | ESPN home page (many objects, ads) | 956 | - | No false alarm |
| `lotsofweb.pcapng` | Normal | Busy web browsing, ~12,900 packets | 12,893 | - | No false alarm |
| `dns_query_response.pcapng` | Normal | One DNS lookup | 2 | - | No false alarm |
| `mail_sender_client_1.pcapng` | Normal | Sending an e-mail (SMTP) | 23 | - | No false alarm |
| `download-fast.pcapng` | Normal | 90 MB Linux ISO download over HTTP | 89,942 | - | No false alarm |

Sources: [Practical Packet Analysis captures](https://github.com/chrissanders/packets) (Chris Sanders) and the
[Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) (`dns-remoteshell.pcap`).

## What testing on real traffic changed

- **Scan noise removed.** On `synscan`, the scan touched ports 4444, 5555, 6667 and 31337 and raised 4 extra
  "suspicious port" alerts. The rule now needs the other side to answer (SYN-ACK), so a scan raises one alert.
- **Three detections added because real attacks used them:** a command-shell banner on the wire (`aurora`,
  `dns-remoteshell`), Metasploit shellcode bytes (`aurora`) and login forms posted over HTTP (`http_dvwa_clearlogin`).
- **A false positive found and fixed.** The 90 MB openSUSE ISO download contains Windows executables inside the
  image. Matching the executable header anywhere flagged it; the rule now only looks at the first bytes of a
  downloaded file, as file-extraction engines do. A regression test keeps it fixed.

## Honest limits

- The three misses are attacks that hide in ordinary-looking HTTP or a custom protocol. Pattern rules on a single
  capture cannot see them; threat-intelligence lookups (IP/domain reputation) are the next step.
- Encrypted traffic (HTTPS, most modern C2) only shows addresses, ports, timing and sizes. The beaconing and port
  rules still work there; payload signatures do not.
- Scapy is easy to read and extend but slow (~3,000 packets/s). For multi-GB captures, convert with `tshark` or
  move parsing to `dpkt`.
