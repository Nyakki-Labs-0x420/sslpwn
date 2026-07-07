# sslpwn

**Version 2.1.0**

sslpwn is a security research tool for testing HTTPS servers against eleven SSL/TLS vulnerabilities. It performs both detection and full cryptographic exploitation, recovering known test secrets to prove practical impact. The tool also includes an adaptive evasion system that rotates network identity, browser fingerprint, and TLS client certificates when rate limiting is encountered.

---

## Vulnerabilities Covered

| Attack | CVE | Description |
|--------|-----|-------------|
| BEAST | CVE-2011-3389 | TLS 1.0 CBC IV reuse |
| Lucky13 | CVE-2013-0169 | CBC padding oracle timing attack |
| BREACH | CVE-2013-3587 | HTTP compression side-channel |
| POODLE | CVE-2014-3566 | SSLv3 padding oracle |
| CRIME | CVE-2012-4929 | TLS compression attack |
| Heartbleed | CVE-2014-0160 | TLS heartbeat memory leak |
| Ticketbleed | CVE-2016-9244 | SessionTicket memory leak (F5 BIG-IP) |
| ROBOT | CVE-2017-6168 | Bleichenbacher RSA padding oracle |
| Renegotiation | CVE-2009-3555 | TLS renegotiation plaintext injection |
| FREAK | CVE-2015-0204 | Export RSA key downgrade |
| Logjam | CVE-2015-4000 | Export DHE downgrade |

---

## Features

- Concurrent scanning of all eleven vulnerabilities using `asyncio` and `aiohttp` for non-blocking I/O.
- Interactive prompt to start exploitation after scanning (skippable with `-y`).
- Full exploit implementations that recover user-supplied test cookies or tokens.
- Adaptive rate-limiting evasion with exponential backoff, VPN rotation, browser fingerprint swapping, and per-profile TLS client certificate generation.
- Built-in device profiles including viewport, screen resolution, colour depth, DPR, device memory, and locale.
- Mullvad VPN integration with automatic country matching to the active device profile.
- Multi-format report generation (Markdown, plain text, HTML).
- Graceful interrupt handling that saves results on Ctrl+C.
- **Quantum-Ready Factoring Pipeline (Experimental)**: Submits Shor's algorithm circuits to the OpenQuantum platform (Rigetti Cepheus-1-108Q) for factoring small RSA moduli (≤ 31 bits).
- **Quantum Random Number Generation (QRNG)**: Fetches true quantum randomness from free REST APIs (atomadic.tech, freeuniversesplitter.com, lizaonair.com) for evasion backoff jitter, profile selection, and TLS certificate serial numbers.
- **Oracle Confidence Check**: Pre-flight validation of Bleichenbacher oracles to abort early if patched, preventing wasted requests.
- **Stabilisation Phase (BREACH/CRIME)**: Dummy requests before each guess to keep compression dictionaries consistent.

---

## Disclaimer

This tool is intended exclusively for authorised security testing on systems you own or have explicit permission to test. Unauthorised use is illegal. The authors accept no liability for misuse.

---

## Installation

### Prerequisites

- Python 3.9 or later
- Mullvad CLI (optional, for VPN rotation)
- A valid Mullvad account if VPN rotation is desired
- An OpenQuantum account (free tier available) if you want to use the quantum factoring pipeline. You will need a Client ID and Client Secret from the dashboard.

### From Source

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
- `qiskit>=1.0.0`
- `openquantum-sdk>=0.3.7`
- `openquantum-sdk-qiskit>=0.1.0`
- `python-dotenv>=1.0.0`

---

## Quantum Acceleration Setup

To enable the quantum factoring pipeline, you must save your OpenQuantum credentials once using the SDK. This stores the Client ID and Client Secret in your local keyring.

### 1. Get Your Credentials

Log in to the [OpenQuantum Dashboard](https://openquantum.com), navigate to **SDK Keys**, and create a new key. Copy the **Client ID** and **Client Secret** (the secret is shown only once; save it immediately).

### 2. Save the Credentials

Run the following command (replace `YOUR_CLIENT_ID` and `YOUR_CLIENT_SECRET` with your actual values):

```bash
python -c "
from openquantum_sdk.auth import ClientCredentials
from openquantum_sdk.qiskit import OpenQuantumService

OpenQuantumService.save_account(
    name='default',
    creds=ClientCredentials(
        client_id='YOUR_CLIENT_ID',
        client_secret='YOUR_CLIENT_SECRET'
    ),
    use_keyring=True
)
print('Credentials saved successfully!')
"
```

Alternatively, you can set environment variables:

```bash
export OPENQUANTUM_CLIENT_ID=your_client_id
export OPENQUANTUM_CLIENT_SECRET=your_client_secret
```

**Note:** The Qiskit provider may still require the `save_account` step to fetch backend capabilities, so it is recommended to run the `save_account` command at least once.

---

## QRNG Setup

The QRNG module works out-of-the-box with no configuration. It uses public, free APIs:

- `atomadic.tech` – formally verified quantum entropy (no sign-up, no API key)
- `freeuniversesplitter.com` – combines seven quantum sources (no sign-up)
- `lizaonair.com` – ANU quantum vacuum fluctuations (no sign-up)

No sign-up, no API key, no rate limits. Just enable `--quantum-rng` and it works. The QRNG APIs are used as the **primary** source of entropy; if all QRNG sources fail, the tool falls back to `secrets.SystemRandom()` (OS-level CSPRNG).

---

## Usage

### Scan Mode

```bash
sslpwn --scan https://target.com
```

Scans for all eleven vulnerabilities concurrently. A report is written to `reports/<hostname>/report.{md,txt,html}`. If vulnerabilities are found, you will be asked whether to exploit them. Use `-y` to skip the prompt.

**Credentials for exploitation:**
- Cookie-based attacks (BEAST, Lucky13, POODLE, Heartbleed, Ticketbleed, ROBOT, Renegotiation) require `--cookie-name` and `--cookie-value`.
- Compression-based attacks (BREACH, CRIME) require `--token-parameter`.

If these are not provided on the command line, the tool will ask for them interactively after the scan.

### Single Module Exploitation

```bash
sslpwn --module beast https://target.com --cookie-name session --cookie-value supersecret
```

### With Quantum Acceleration

```bash
sslpwn --scan https://target.com --quantum --quantum-backend rigetti:cepheus-1-108q
```

The tool will automatically attempt to factor any RSA modulus ≤ 31 bits using Shor's algorithm on the specified QPU. For larger moduli, it falls back to classical attacks.

### With Quantum Randomness (QRNG)

```bash
sslpwn --scan https://target.com --quantum-rng --adaptive
```

This uses true quantum randomness for:
- Evasion backoff jitter
- Profile selection (which device fingerprint to use)
- TLS certificate serial numbers

---

### Command-Line Options

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
| **Quantum Acceleration** | |
| `--quantum` | Enable quantum acceleration using OpenQuantum Qiskit provider |
| `--quantum-backend` | OpenQuantum backend ID (default: `rigetti:cepheus-1-108q`) |
| `--quantum-shots` | Number of shots for quantum circuits (default 1024) |
| `--quantum-timeout` | Timeout in seconds for quantum jobs (default 600) |
| **QRNG** | |
| `--quantum-rng` | Use true quantum randomness (QRNG) for evasion and crypto operations |

---

### Examples

Scan with adaptive evasion, 8 concurrent tasks, auto-exploit, and quantum acceleration:

```bash
sslpwn --scan https://vulnerable.example.com -y \
    --cookie-name session --cookie-value abc123 \
    --token-parameter q --adaptive --threads 8 --quantum
```

Exploit a single module with quantum factoring and QRNG:

```bash
sslpwn --module robot https://target.com \
    --cookie-name auth_token --cookie-value xyz789 \
    --quantum --quantum-rng
```

Scan with QRNG-enhanced evasion (no quantum factoring):

```bash
sslpwn --scan https://target.com --quantum-rng --adaptive
```

---

## How It Works

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

### Timing-Sensitive Exploits (Lucky13, ROBOT, BEAST)

These attacks rely on sub-millisecond timing differences. To maximise accuracy:

- Exploits run in strictly sequential, single-threaded loops.
- Each measurement uses `time.perf_counter()` for high resolution.
- The top and bottom 5% of RTT samples are discarded to remove network jitter.
- A median is taken from the remaining samples.

This design is necessary because network jitter can otherwise drown out the cryptographic signal (AlFardan and Paterson 2013).

### Quantum Factoring (ROBOT Attack)

When `--quantum` is enabled and the server offers an RSA key exchange:

1. The tool extracts the RSA modulus (N) from the server certificate.
2. If N is ≤ 31 bits, it builds a Shor's algorithm circuit using Qiskit (with `n` qubits for the modulus and `2n` for the exponent, plus auxiliaries).
3. The circuit is transpiled, submitted to the OpenQuantum backend using the `SamplerV2` primitive, and polled for completion.
4. Measurement counts are post-processed using continued fractions to find the period `r`.
5. From `r`, factors `p` and `q` are computed, and the private exponent `d` is derived to decrypt the captured premaster secret.
6. If quantum fails or N is too large, the tool falls back to the classical Bleichenbacher padding-oracle attack (Bleichenbacher 1998).

### Quantum Random Number Generation (QRNG)

When `--quantum-rng` is enabled:

1. The tool fetches true quantum randomness from a free REST API (atomadic.tech, freeuniversesplitter.com, or lizaonair.com).
2. For evasion backoff jitter, the jitter factor is derived from quantum entropy, making request intervals statistically unbiased and unpredictable.
3. Profile selection (which device fingerprint to use) is driven by quantum randomness, preventing pattern learning.
4. TLS certificate serial numbers are generated using quantum entropy, making them impossible to correlate.
5. If any QRNG API fails, the tool automatically falls back to `secrets.SystemRandom()`.

**Why QRNG matters:** Classical PRNGs (even CSPRNGs) are deterministic; given the same seed, they produce the same sequence. QRNG is fundamentally non-deterministic, making evasion truly unpredictable.

### Adaptive Evasion

When enabled with `--adaptive`, the tool monitors HTTP status codes (403, 404, 420, 429, 500, 502, 503), `Retry-After` headers, and connection errors. If the number of consecutive indicators reaches the threshold, an evasion cycle is triggered:

1. Exponential backoff with quantum-driven jitter (if `--quantum-rng` is set).
2. VPN IP rotation (if available), using the new device profile's country code to select an exit node.
3. Replacement of the entire browser fingerprint: User-Agent, Sec-CH-UA headers, viewport, screen resolution, colour depth, DPR, device memory, and TLS cipher preferences.
4. Generation of a new self-signed X.509 client certificate with quantum-random serial numbers (if `--quantum-rng` is set).

This cycle repeats each time rate limiting is detected, making successive requests appear to originate from different devices, browsers, and geographic locations.

---

## Quantum-Ready Factoring Pipeline: Limitations and Trade-Offs

The quantum factoring pipeline is an **experimental research feature**. The following limitations apply:

### What Works Today

- Building Shor's algorithm circuits using Qiskit.
- Submitting circuits to the Rigetti Cepheus-1-108Q QPU (108 qubits).
- Factoring RSA moduli up to **31 bits** (N ≤ 2³¹).
- Deriving private keys from quantum-found factors.
- Seamless fallback to classical attacks when quantum is unavailable.

### Why This Does Not Break Real RSA

| RSA Key Size | Logical Qubits Required (Shor) | Feasible Today? |
|--------------|-------------------------------|-----------------|
| 31 bits      | ~62                           | Yes (demo)      |
| 512 bits     | ~1,024                        | No              |
| 2048 bits    | ~2,300 to 20 million*         | No              |
| 4096 bits    | ~3,971                        | No              |

*Estimates vary significantly. Chevignard, Fouque, and Schrottenloher (2025) estimate ~2,314 logical qubits for RSA-2048, while Gidney and Ekerå (2021) estimate 20 million physical qubits with error correction.

**Current quantum computers are NISQ (Noisy Intermediate-Scale Quantum) devices** (Preskill 2018):
- Limited to ~100 to 200 physical qubits (and many are used for error correction).
- High gate error rates (1 to 5%) limit circuit depth.
- Shor's algorithm requires thousands of **error-corrected** logical qubits.

For a 2048-bit RSA key, you would need:
- ~2,300 to 4,096 logical qubits (for Shor's algorithm).
- Each logical qubit requires ~1,000 physical qubits (with current error correction).
- That is millions of physical qubits, which are decades away.

The Rigetti Cepheus-1-108Q used in this pipeline has 108 physical qubits with 99.1% median two-qubit gate fidelity and 99.9% median single-gate fidelity. This is insufficient for factoring real RSA keys but sufficient for research demonstrations.

### What This Integration Is Useful For

1. **Demonstration**: Proves that the tool chain works: Qiskit to OpenQuantum to QPU to factors to decryption.
2. **Research**: Test Shor's algorithm on real hardware with small numbers.
3. **Future-proofing**: As QPUs improve, the same code will work for larger keys (just update the qubit limit).
4. **Education**: See how quantum factoring actually works in practice.

### What It Does Not Do

- Break real 2048-bit RSA keys.
- Speed up BREACH or CRIME attacks (these are network-bound, not compute-bound).
- Replace classical attacks for production use.

### Recommendation

Enable quantum acceleration (`--quantum`) for research and demonstration purposes. For real-world security testing, the classical attacks (Bleichenbacher, timing attacks, etc.) are still the practical approach. The tool will automatically fall back to classical methods when quantum is not applicable.

---

## QRNG Trust Model

The QRNG module uses public APIs as the **primary** source of entropy:

- [atomadic.tech](https://atomadic.tech) – formally verified quantum entropy
- [freeuniversesplitter.com](https://freeuniversesplitter.com) – combines seven quantum sources
- [lizaonair.com](https://lizaonair.com) – ANU quantum vacuum fluctuations

If any QRNG API fails or times out, the tool automatically falls back to `secrets.SystemRandom()` (OS-level CSPRNG). No sensitive data is ever sent to QRNG APIs; only raw integer requests for random numbers are transmitted.

**Why QRNG first:** Quantum entropy is fundamentally unpredictable, making evasion and cryptographic operations truly non-deterministic and resistant to pattern analysis.

---

## Limitations of Classical Attacks

### BREACH and CRIME

BREACH and CRIME are compression-side-channel attacks. They rely on:

- The ability to repeatedly inject chosen plaintext and observe response sizes.
- A consistent compression dictionary across requests.
- A target secret that appears in the response body (BREACH) or TLS headers (CRIME).

**Practical limitations:**
- If the target uses a CSRF token that changes per request, the attack breaks.
- If the server uses dynamic compression dictionaries, the oracle becomes unstable.
- The attack requires thousands of requests and a response size difference of often just 1 byte.

To mitigate these issues, the tool uses a stabilisation dummy request before each guess to warm up the compression context.

### Lucky13

Lucky13 is a timing padding oracle attack. It relies on sub-millisecond timing differences across hundreds of thousands of requests.

**Practical limitations:**
- Network jitter can drown out the cryptographic signal.
- The attack requires many samples to overcome noise.
- Servers with constant-time implementations are not vulnerable.

The tool mitigates this by using strictly sequential, single-threaded loops, discarding top/bottom 5% of RTT samples, and taking a median.

### ROBOT

ROBOT is a Bleichenbacher padding oracle attack. It requires:
- An oracle that leaks whether PKCS#1 v1.5 padding is valid.
- Thousands of oracle queries.

**Practical limitations:**
- Many servers have been patched since 2017.
- Forward secrecy (ECDHE) protects against passive decryption.
- The attack requires a noisy oracle; many servers time out uniformly, breaking the attack.

The tool includes an oracle confidence check before running the full exploit to abort early if patched.

---

## Output and Reports

Results are saved in `reports/<hostname>/` as three files:

- `report.md`
- `report.txt`
- `report.html`

A raw log file `<hostname>_sslpwn_results.txt` is also written to the output directory. If the tool is interrupted with Ctrl+C, pending results are saved before exit.

---

## Planned Updates (v3)

The following features are under development for the next release:

- **Tor network integration**: Route all traffic through the Tor network, including automatic circuit rotation and hidden service scanning.
- **Extended device profile library**: Additional device profiles covering more phones, tablets, laptops, and IoT devices, each with accurate screen metrics and TLS fingerprints.
- **Proxy chain support**: Chaining of SOCKS5 and HTTP proxies before the VPN exit for additional anonymity layers.
- **Custom JA3/JA4 fingerprint injection**: Full control over the TLS client hello fingerprint to mimic specific browsers beyond the currently supported ciphers.
- **Adaptive Noise Injection**: Random HTTP headers and parameter shuffling to avoid WAF fingerprinting (planned, not yet implemented).
- **Additional exploits**: DROWN, POODLE TLS, Zombie POODLE, and GOLDENDOODLE attacks.

---

## References

AlFardan, N.J. and Paterson, K.G., 2013. Lucky Thirteen: Breaking the TLS and DTLS Record Protocols. *IEEE Symposium on Security and Privacy*, pp.526-540.

Bleichenbacher, D., 1998. Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1. *Advances in Cryptology – CRYPTO '98*, pp.1-12.

Chevignard, C., Fouque, P.A. and Schrottenloher, A., 2025. *Re: [Cryptography] Has quantum cryptanalysis actually achieved anything?* Marc.info.

Gidney, C. and Ekerå, M., 2021. How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits. *Quantum*, 5, p.433.

Preskill, J., 2018. Quantum Computing in the NISQ era and beyond. *Quantum*, 2, p.79.

Rigetti Computing, 2026. *Cepheus-1-108Q System Specifications*. Quantum Computing Report.

Open Quantum, 2025. *Open Quantum Platform: Quantum Computing for All*. Quantum Rings.

*BREACH: HTTP Compression Side-Channel Attack*, 2013. Wikipedia.

*Return Of Bleichenbacher's Oracle Threat (ROBOT)*, 2017. Qualys Threat Protection.

*Quantum Random Number Generator (QRNG)*, Outshift by Cisco.

---

## License

sslpwn is licensed under the GNU Affero General Public License v3.0 or later (AGPLv3+). See the `LICENSE` file for the full text.

---

## Contributing

Contributions are welcome. Please ensure code passes standard Python linters, new modules are fully implemented without stubs, and secure coding practices are followed.

---

## Acknowledgements

This project combines and extends public proofs of concept for the listed vulnerabilities into a single tool for practical security testing. Quantum acceleration is powered by the [OpenQuantum](https://openquantum.com) platform and the Rigetti Cepheus-1-108Q QPU. QRNG is powered by [atomadic.tech](https://atomadic.tech), [freeuniversesplitter.com](https://freeuniversesplitter.com), and [lizaonair.com](https://lizaonair.com).
