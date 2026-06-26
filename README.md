# sslpwn

sslpwn is a security research tool for testing HTTPS servers against eleven SSL/TLS vulnerabilities. It performs both detection and full cryptographic exploitation, recovering known test secrets to prove practical impact. The tool also includes an adaptive evasion system that rotates network identity, browser fingerprint, and TLS client certificates when rate limiting is encountered.

## Vulnerabilities covered

| Attack       | CVE            | Description                                        |
|--------------|----------------|----------------------------------------------------|
| BEAST        | CVE-2011-3389  | TLS 1.0 CBC IV reuse                               |
| Lucky13      | CVE-2013-0169  | CBC padding oracle timing attack                   |
| BREACH       | CVE-2013-3587  | HTTP compression side-channel                      |
| POODLE       | CVE-2014-3566  | SSLv3 padding oracle                               |
| CRIME        | CVE-2012-4929  | TLS compression attack                             |
| Heartbleed   | CVE-2014-0160  | TLS heartbeat memory leak                          |
| Ticketbleed  | CVE-2016-9244  | SessionTicket memory leak (F5 BIG-IP)              |
| ROBOT        | CVE-2017-6168  | Bleichenbacher RSA padding oracle                  |
| Renegotiation| CVE-2009-3555  | TLS renegotiation plaintext injection              |
| FREAK        | CVE-2015-0204  | Export RSA key downgrade                           |
| Logjam       | CVE-2015-4000  | Export DHE downgrade                               |

## Features

- Scan mode that checks all eleven vulnerabilities concurrently using asyncio and aiohttp for non-blocking I/O.
- Interactive prompt to start exploitation after scanning (can be skipped with `-y`).
- Full exploit implementations that recover user-supplied test cookies or tokens.
- Adaptive rate-limiting evasion with exponential backoff, VPN rotation, browser fingerprint swapping, and per-profile TLS client certificate generation.
- Built-in set of realistic device profiles including viewport, screen resolution, colour depth, DPR, device memory, and locale.
- Mullvad VPN integration with automatic country matching to the active device profile.
- Multi-format report generation (Markdown, plain text, HTML).
- Graceful interrupt handling that saves results on Ctrl+C.

## Disclaimer

This tool is intended exclusively for authorised security testing on systems you own or have explicit permission to test. Unauthorised use is illegal. The authors accept no liability for misuse.

## Installation

### Prerequisites

- Python 3.9 or later
- Mullvad CLI (optional, for VPN rotation)
- A valid Mullvad account if VPN rotation is desired

### From source

```bash
git clone https://github.com/Nyakki-Labs-0x420/sslpwn.git
cd sslpwn
pip install .
```

The `sslpwn` command will be available in your PATH.

### Dependencies

All required packages are declared in `pyproject.toml` and installed automatically:

- `requests>=2.28.0`
- `urllib3>=1.26.12`
- `rich>=13.0.0`
- `pyasn1>=0.4.8`
- `cryptography>=41.0.0`
- `aiohttp>=3.9.0`

## Usage

### Scan mode

```bash
sslpwn --scan https://target.com
```

Scans for all eleven vulnerabilities concurrently using asyncio. A report is written to `reports/<hostname>/report.{md,txt,html}`. If vulnerabilities are found, you will be asked whether to exploit them. Use `-y` to skip the prompt.

**Credentials for exploitation:**
- Cookie-based attacks (BEAST, Lucky13, POODLE, Heartbleed, Ticketbleed, ROBOT, Renegotiation) require `--cookie-name` and `--cookie-value`.
- Compression-based attacks (BREACH, CRIME) require `--token-parameter`.

If these are not provided on the command line, the tool will ask for them interactively after the scan.

### Single module exploitation

```bash
sslpwn --module beast https://target.com --cookie-name session --cookie-value supersecret
```

### Command-line options

| Option | Description |
|--------|-------------|
| `target` | Target HTTPS URL |
| `--scan` | Scan for all vulnerabilities, then optionally exploit |
| `--module` | Exploit a single module (choices: `beast`, `lucky13`, `breach`, `poodle`, `crime`, `heartbleed`, `ticketbleed`, `robot`, `renegotiation`, `freak`, `logjam`) |
| `--cookie-name` | Cookie name to decrypt (cookie-based modules) |
| `--cookie-value` | Known test cookie value |
| `--token-parameter` | GET parameter that reflects a secret (BREACH/CRIME) |
| `--mask-length` | Mask length for BREACH/CRIME (default 10) |
| `--user-agent-file` | File with custom User-Agent strings (one per line) |
| `--rate` | Requests per second (default 2.0) |
| `--output-dir` | Directory for output files (default: current directory) |
| `--no-vpn` | Disable Mullvad VPN rotation |
| `--adaptive` | Enable adaptive evasion with TLS client certificate generation |
| `--adaptive-threshold` | Consecutive errors before evasion (default 3) |
| `--adaptive-backoff-base` | Initial backoff time in seconds (default 1.0) |
| `--adaptive-max-backoff` | Maximum backoff time in seconds (default 60.0) |
| `--threads` | Number of concurrent tasks for scanning (default 4) |
| `-y`, `--yes` | Auto-answer yes to exploitation prompt |
| `--version` | Show version and exit |

### Examples

Scan with adaptive evasion and 8 concurrent tasks, auto-exploit:

```bash
sslpwn --scan https://vulnerable.example.com -y \
    --cookie-name session --cookie-value abc123 \
    --token-parameter q --adaptive --threads 8
```

Scan with custom evasion thresholds:

```bash
sslpwn --scan https://target.com --adaptive --adaptive-threshold 2 \
    --adaptive-backoff-base 2.0 --adaptive-max-backoff 120 --threads 4
```

Exploit a single module with adaptive evasion:

```bash
sslpwn --module lucky13 https://target.com \
    --cookie-name auth_token --cookie-value xyz789 --adaptive
```

## How it works

### Scanning

Scanning is performed asynchronously using `asyncio` and `aiohttp`. Each attack module's `check_vulnerability_async()` method is run as a coroutine, with a semaphore controlling the maximum number of concurrent checks. This design allows the tool to perform many network probes in parallel without the overhead of operating system threads.

- BEAST, Lucky13, POODLE: attempt handshakes with the specific protocol version and CBC ciphers.
- CRIME: check if TLS compression is accepted.
- BREACH: compare response sizes with and without compression.
- Heartbleed: send a heartbeat request and verify the response.
- Ticketbleed: send a ClientHello with a malformed SessionTicket extension and look for a NewSessionTicket message.
- ROBOT: check if the server offers an RSA key exchange cipher.
- Renegotiation: attempt a client-initiated renegotiation.
- FREAK: check if export RSA ciphers are accepted.
- Logjam: check if export DHE ciphers are accepted.

### Exploitation

After the scan, full exploits are available. Each module's `exploit()` method performs the actual cryptographic attack and verifies the result against a known test secret. For cookie-based attacks, the tool decrypts the supplied cookie from the encrypted traffic. For compression-based attacks, it recovers the reflected token byte by byte. Renegotiation injects a plaintext request into an existing TLS session. FREAK and Logjam log the server's weak public parameters for offline factoring.

### Adaptive evasion

When enabled with `--adaptive`, the tool monitors HTTP status codes (403, 404, 420, 429, 500, 502, 503), `Retry-After` headers, and connection errors. If the number of consecutive indicators reaches the threshold, an evasion cycle is triggered:

1. Exponential backoff with random jitter.
2. VPN IP rotation (if available), using the new device profile's country code to select an exit node.
3. Replacement of the entire browser fingerprint: User-Agent, Sec-CH-UA headers, viewport, screen resolution, colour depth, DPR, device memory, and TLS cipher preferences.
4. Generation of a new self-signed X.509 client certificate with subject fields matching the selected profile.

This cycle repeats each time rate limiting is detected, making successive requests appear to originate from different devices, browsers, and geographic locations.

## Output and reports

Results are saved in `reports/<hostname>/` as three files:

- `report.md`
- `report.txt`
- `report.html`

A raw log file `<hostname>_sslpwn_results.txt` is also written to the output directory. If the tool is interrupted with Ctrl+C, pending results are saved before exit.

## Planned updates (v3)

The following features are under development for the next release:

- **Tor network integration**: Ability to route all traffic through the Tor network, including automatic circuit rotation and hidden service scanning.
- **Extended device profile library**: Additional device profiles covering more phones, tablets, laptops, and IoT devices, each with accurate screen metrics and TLS fingerprints.
- **Proxy chain support**: Chaining of SOCKS5 and HTTP proxies before the VPN exit for additional anonymity layers.
- **Custom JA3/JA4 fingerprint injection**: Full control over the TLS client hello fingerprint to mimic specific browsers beyond the currently supported ciphers.
- **Additional exploits**: DROWN, POODLE TLS, Zombie POODLE, and GOLDENDOODLE attacks.

## License

sslpwn is licensed under the GNU Affero General Public License v3.0 or later (AGPLv3+). See the `LICENSE` file for the full text.

## Contributing

Contributions are welcome. Please ensure code passes standard Python linters, new modules are fully implemented without stubs, and secure coding practices are followed.

## Acknowledgements

This project combines and extends public proofs of concept for the listed vulnerabilities into a single tool for practical security testing.
