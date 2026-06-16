# AUR Threat Mitigator

A lightweight offline static analysis utility to audit local ALPM metadata and AUR helper build caches for compromised packages and suspicious code patterns.

## Features

- **Package Validation**: Cross-references local foreign packages against an offline threat manifest.
- **Deep Cache Scanning**: Sweeps `yay`, `paru`, `aurutils`, and `/var/cache/aur` directories.
- **Static Content Analysis**: Uses optimized regex matching to catch common obfuscation techniques and out-of-band execution hooks inside `PKGBUILD` and `install` scripts.
- **Zero Network Footprint**: Operates entirely locally with zero telemetry or dynamic web lookups.

## Heuristics Tracked

- Remote execution pipes (`curl`, `wget` piped to `sh`, `bash`, `node`, `python`)
- Base64 encoding pipelines (`base64 -d`, `openssl enc -base64`)
- Direct interactive reverse shells and network sockets (`/dev/tcp/`, `/dev/udp/`)
- Suspicious helper/native utilities (`netcat`, `nc`, `socat`)
- Hex-encoded string layout obfuscation (`\xHEX`)
- Unauthorized build-time package executions (`npm install`)

## Requirements

- Python 3.x
- Arch Linux environment (`pacman` binary)

## Setup & Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/PicasoTheDealer/AUR-threat-mitigator.git
   cd AUR-threat-mitigator
   ```
2. Place your list of known compromised package names in a file named `packages.txt` (one package name per line) in the same directory as the script.

3. Execute the audit:
  ```bash
  python3 aur-audit.py
  ```

## Output Targets

`Clean`: Outputs [+] Found nothing in green and exits with code 0.

`Anomalies Detected`: Outputs specific trigger events along with file paths in red and exits with code 1.
