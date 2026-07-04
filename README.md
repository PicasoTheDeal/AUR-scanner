# AUR-scanner

A lightweight offline static analysis utility to scan local ALPM metadata and AUR helper build caches for compromised packages and suspicious code patterns.

## Features

- **Package Validation**: Cross-references local foreign packages against an offline threat manifest.

- **Deep Cache Scanning**: Sweeps `yay`, `paru`, `aurutils`, and `/var/cache/aur` directories.

- **Static Content Analysis**: Uses optimized regex matching to catch common obfuscation techniques and out-of-band execution hooks inside `PKGBUILD` and `install` scripts.

- **Zero Network Footprint**: Operates entirely locally with zero telemetry or dynamic web lookups.

## Heuristics Tracked

- Remote execution pipes (`curl`, `wget` piped to `sh`, `bash`, `node`, `python`)
- Base64 encoding pipelines (`base64 -d`, `openssl enc -base64`, `echo | base64`)
- Direct interactive reverse shells and network sockets (`/dev/tcp/`, `/dev/udp/`)
- Suspicious helper/native network utilities (`netcat`, `nc`, `socat`)
- Hex-encoded string layout obfuscation (`\xHEX`)
- Unauthorized build-time package executions (`npm install`)

## Disclaimer & Limitations

`aur-scanner` is a static signature and heuristic auditing tool, **not** a kernel-level EDR or full antivirus solution. 

- **Bypasses**: Static regex tracking can be bypassed via advanced runtime obfuscation, dynamic payload fetching inside compiled binaries (`.so` or executables), or custom encryption (e.g., non-standard OpenSSL flags). It is designed to catch low-hanging fruit and sloppy, un-obfuscated script injections.

- **False Positives**: Because it flags structural anomalies, benign build scripts utilizing complex shell loops or raw hex arrays may trigger alerts. Findings should be manually audited.

## Requirements

- Python 3.x

- Arch Linux environment (`pacman` binary)

## Setup & Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/PicasoTheDealer/AUR-scanner.git
   cd aur-scanner
   ```

2. Place your list of known compromised package names in a file named `packages.txt` (one package name per line) in the same directory as the script.

3. Execute the scan:

   ```bash
   python3 aur-audit.py
   ```
   
## Output Targets & Verdicts
   
   [+] Found nothing (Green, Exit Code 0): No signatures matched. Environment matches current baseline configuration thresholds.

   [!] [Path]: Trigger [Pattern] (Red, Exit Code 1): Code-level anomaly detected.
   
   **Note**: If a heuristic trigger is verified inside an installed package metadata or local cache, assume the host environment is compromised. Standard pacman -R removals may be insufficient if out-of-band execution occurred during the build/install phase. Immediate forensic triage or system re-installation is recommended.

## Credits and Acknowledgments

 - Members of the EndeavourOS, CachyOS, and Arch Linux communities for technical feedback
