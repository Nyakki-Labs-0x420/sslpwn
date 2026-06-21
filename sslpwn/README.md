# sslpwn

sslpwn is a security research tool for testing web applications against eight well-known SSL/TLS vulnerabilities:

- **BEAST** (CVE-2011-3389) - TLS 1.0 CBC IV reuse
- **Lucky13** (CVE-2013-0169) - CBC padding oracle timing attack
- **BREACH** (CVE-2013-3587) - HTTP compression side-channel
- **POODLE** (CVE-2014-3566) - SSLv3 padding oracle
- **CRIME** (CVE-2012-4929) - TLS compression attack
- **Heartbleed** (CVE-2014-0160) - TLS heartbeat memory leak
- **Ticketbleed** (CVE-2016-9244) - SessionTicket memory leak (F5 BIG-IP)
- **ROBOT** (CVE-2017-6168) - Bleichenbacher RSA padding oracle

sslpwn does not merely detect the presence of a vulnerability. It performs the full cryptographic exploit against a target server and recovers a known test secret to demonstrate practical exploitability.

## Features

- Scan mode that checks all eight vulnerabilities in one run
- Interactive prompt (or `-y` flag) to start exploitation after scanning
- Full exploit implementation for each vulnerability (requires user-supplied test cookie or token)
- Adaptive rate-limiting evasion: automatic backoff, VPN IP rotation, and browser fingerprint spoofing when rate limits are detected
- Rotating User-Agent strings with matching device profiles (viewport, DPR, platform headers)
- Mullvad VPN integration for IP rotation (optional)
- Rich console output with random startup banners
- Reports generated in Markdown, plain text, and HTML formats
- Graceful interrupt handling (Ctrl+C saves current results)

## Disclaimer

This tool is intended exclusively for authorised security research, bug bounty programs, and penetration testing on systems you own or have explicit permission to test. Using it against targets without authorisation is illegal and unethical. The authors assume no liability for misuse.

## Installation

### Prerequisites

- Python 3.9 or later
- [Mullvad CLI](https://mullvad.net/en/help/install-mullvad-app/) (optional, for VPN rotation)
- A valid Mullvad account if VPN rotation is desired

### From source

```bash
git clone https://github.com/yourorg/sslpwn.git
cd sslpwn
pip install .
```

After installation, the `sslpwn` command is available in your PATH.

### Dependencies

All required Python packages are declared in `pyproject.toml` and installed automatically:

- `requests >= 2.28.0`
- `urllib3 >= 1.26.12`
- `rich >= 13.0.0`
- `pyasn1 >= 0.4.8` (for RSA certificate parsing)

## Usage

### Scan mode (recommended)

```bash
sslpwn --scan https://target.com
```

This checks all eight vulnerabilities and writes a report to `reports/<hostname>/report.{md,txt,html}`. If any vulnerabilities are found, you will be asked whether you want to exploit them. Use `-y` to skip the prompt and exploit automatically.

**Required credentials for exploitation:**
- Cookie-based attacks (BEAST, Lucky13, POODLE, Heartbleed, Ticketbleed, ROBOT) require `--cookie-name` and `--cookie-value`.
- Compression-based attacks (BREACH, CRIME) require `--token-parameter`.

If you do not provide them via command line, sslpwn will ask for them interactively after the scan.

### Single module exploitation

```bash
sslpwn --module beast https://target.com --cookie-name session --cookie-value supersecret
```

Runs the full exploit for one vulnerability and generates a report in the `reports/` folder.

### Command-line options

| Option | Description |
|--------|-------------|
| `target` | Target HTTPS URL (e.g. `https://example.com`) |
| `--scan` | Scan for all vulnerabilities, then optionally exploit |
| `--module MODULE` | Exploit a single module (choices: `beast`, `lucky13`, `breach`, `poodle`, `crime`, `heartbleed`, `ticketbleed`, `robot`) |
| `--cookie-name NAME` | Cookie name to decrypt (required for cookie-based modules) |
| `--cookie-value VALUE` | Known test cookie value for verification |
| `--token-parameter PARAM` | GET parameter that reflects a secret in the response body (BREACH/CRIME) |
| `--mask-length N` | Padding mask length for BREACH/CRIME (default 10) |
| `--user-agent-file FILE` | File with custom User-Agent strings (one per line) |
| `--rate R` | Requests per second (default 2.0) |
| `--output-dir DIR` | Directory for output files (default: current directory) |
| `--no-vpn` | Disable Mullvad VPN IP rotation |
| `--adaptive` | Enable adaptive rate-limiting evasion |
| `--adaptive-threshold N` | Consecutive errors before evasion triggers (default 3) |
| `--adaptive-backoff-base T` | Initial backoff time in seconds (default 1.0) |
| `--adaptive-max-backoff T` | Maximum backoff time in seconds (default 60.0) |
| `--yes` / `-y` | Automatically answer "yes" to all prompts (exploit all found vulnerabilities) |
| `--version` | Show version and exit |

### Examples

**Scan a target and auto-exploit all vulnerabilities:**

```bash
sslpwn --scan https://vulnerable.example.com -y \
    --cookie-name session --cookie-value abc123 \
    --token-parameter q
```

**Enable adaptive evasion with custom thresholds:**

```bash
sslpwn --scan https://target.com --adaptive --adaptive-threshold 2 \
    --adaptive-backoff-base 2.0 --adaptive-max-backoff 120
```

**Exploit only Lucky13:**

```bash
sslpwn --module lucky13 https://target.com \
    --cookie-name auth_token --cookie-value xyz789
```

## How it works

### Scanning

Each attack module implements a `check_vulnerability()` method that performs a quick, low-impact probe:

- **BEAST / Lucky13 / POODLE:** attempt TLS 1.0 / 1.2 / SSLv3 handshakes with CBC ciphers.
- **CRIME:** check if TLS compression is accepted.
- **BREACH:** compare compressed vs uncompressed response sizes.
- **Heartbleed:** send a small heartbeat request and verify the response.
- **Ticketbleed:** send a ClientHello with a malformed SessionTicket extension and look for a NewSessionTicket response.
- **ROBOT:** check if the server offers an RSA key exchange cipher.

### Exploitation

After the scan, you can choose to run the full exploits. Each exploit module implements a `exploit()` method that performs the actual cryptographic attack and verifies the result against the known test cookie or token.

**For cookie-based attacks:** you must know (and supply) the exact value of a cookie that will be present in the encrypted traffic. The tool decrypts it and compares the recovered value with the original.

**For compression-based attacks:** you must know the name of a GET parameter whose value is reflected in the response body. The tool recovers the reflected value byte by byte.

### Adaptive evasion

When `--adaptive` is enabled, the tool monitors HTTP status codes (429, 503), `Retry-After` headers, and connection errors. If the number of consecutive rate-limit indicators reaches the threshold, sslpwn performs a full evasion cycle:

1. Exponential backoff with random jitter.
2. VPN IP rotation (if Mullvad is available).
3. Replacement of the entire browser fingerprint (User-Agent, Sec-CH-UA headers, viewport dimensions, DPR, platform).

This allows the tool to continue testing even against servers that enforce aggressive rate limiting.

## Output and reports

All results are saved in the `reports/<hostname>/` directory as three files:

- `report.md` - Markdown
- `report.txt` - Plain text
- `report.html` - HTML with basic styling

A raw log file (`<hostname>_sslpwn_results.txt`) is also written to the output directory (default: current directory).

If a scan is interrupted with Ctrl+C, any pending results are saved before exiting.

## License

sslpwn is licensed under the GNU Affero General Public License v3.0 or later (AGPLv3+). See the [LICENSE](LICENSE) file for the full text.

## Contributing

Contributions are welcome. Please ensure that:

- Code passes all Python linters (flake8, pylint, black formatting).
- New modules are fully implemented with no placeholders or stubs.
- Secure coding practices are followed (input validation, no circular imports, proper error handling).
- The license header is included in all new files.

## Acknowledgements

This project extends public proofs of concept for BEAST, Lucky13, BREACH, POODLE, CRIME, Heartbleed, Ticketbleed, and ROBOT. It is intended to provide a single, robust tool for practical testing by security professionals.
