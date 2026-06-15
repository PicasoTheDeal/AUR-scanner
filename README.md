# Atomic Arch Auditor

A minimal, performance-focused, zero-dependency Python utility designed to scan Arch Linux and Arch-based distributions (like EndeavourOS) for indicators of compromise (IOCs) related to the **Atomic Arch** supply chain campaign. 

It queries threat intelligence feeds from **Sonatype** and **SafeDep** to identify compromised AUR installations, hijacked packages, and eBPF kernel rootkits.

## Features
- **Zero External Dependencies:** Built strictly on native Python 3 libraries (`urllib`, `json`, `subprocess`) to ensure safe execution on potentially compromised environments.
- **Dynamic Threat Intel:** Fetches live blocklists and known artifact patterns directly from Sonatype and SafeDep.
- **System Artifact Verification:** Sweeps package manager caches (`~/.npm`, `~/.bun`) and kernel footprints for the `scales.bpf` rootkit.
- **Blast Radius Analysis:** Evaluates dependency mapping via `pacman -Qi` before removing packages to prevent accidental system breakage.

## Installation & Usage

Clone the repository and execute the script directly. It requires no environment setup.

```bash
git clone [https://github.com/PicasoTheDeal/AUR-threat-mitigator.git](https://github.com/PicasoTheDeal/AUR-threat-mitigator.git)
cd atomic-arch-auditor
chmod +x aur-api-audit.py
python3 aur-api-audit.py
```

## Disclaimer

This tool is provided for educational and incident response purposes only. Malware analysis and removal carry inherent risks to system stability. Always back up critical data before executing remediation steps.
