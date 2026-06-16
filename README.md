# AUR Threat Mitigator

A high-performance forensic auditing utility engineered to scan local ALPM (pacman) databases and AUR helper compilation caches for malicious supply-chain injection signatures.

## The Incident: What Happened?

During recent supply-chain vectors hitting the Arch User Repository (AUR), threat actors compromised multiple package maintainer accounts or orphaned packages. The malicious modifications didn't target binary blobs directly; instead, they targeted the compilation life cycle by injecting secondary payload download hooks inside the package's `PKGBUILD` file (specifically targeting hooks like `prepare()` or `build()`).

When users ran an AUR helper to install or update these packages, `makepkg` executed the script, triggering hidden commands like:

* `npm i lockfile-js`
* `npm i atomic-lockfile`

### The Upstream 404 Blindspot

The moment these attacks are discovered, the Arch Security Team and registry operators completely purge the compromised packages from the upstream AUR servers and the npm registry. 

While this stops the spread, it creates a security blindspot: **standard package managers can no longer see or download the infected variants.** If you try to audit or pull down the package to inspect it, you just get a standard `404 Not Found` error. 

**AUR Threat Mitigator** bridges this gap by pivoting entirely to local host forensics—interrogating your system's underlying database and historical build paths for leftover infection footprints.

---

## Technical Architecture & Detection Engine

The script executes a multi-layered forensic pipeline to ensure zero false negatives while avoiding reliance on dead upstream repositories.

### 1. Multi-Feed Intel Muxing


The tool dynamically pulls down and aggregates threat intelligence strings from both official Arch incident tracking ledgers and curated community open-source malware tracking repositories. This builds a real-time memory matrix of blacklisted package identities and behavioral strings.

### 2. Manifest Bypass & Local ALPM Interrogation

The engine prioritizes flexibility by staging its target acquisition in two layers:

* **Offline Manifest Mode:** The tool first looks for a local `packages.txt` file in its root directory. If found, it bypasses live environments to audit that text inventory instead.

* **Live Subsystem Interrogation:** If no manual manifest is found, it taps directly into the local Arch Linux Package Management (ALPM) subsystem. It queries the local registry (`pacman -Qm`), extracting metadata from the `desc` and `install` files of foreign packages to check if a compromised package version was compiled and registered on the host system before the upstream purge occurred.

### 3. Deep Cache Scanning & Multi-Signature Regex Engine

Even if a package was partially removed or failed during build, AUR helpers leave historical build directories on disk. The tool hunts down compilation footprints across the most common AUR helper ecosystems:

* `yay` (`~/.cache/yay/`)
* `paru` (`~/.cache/paru/`)
* `aurutils` (`~/.cache/aurutils/sync/` & `/var/cache/aur/`)

It opens cached `PKGBUILD` and `.install` files, passing their contents through a regex signature engine looking for an expanded matrix of threats, including:
* Known downstream payload implants (`lockfile-js`, `atomic-lockfile`)
* Obfuscated identity harvesters and delivery tokens (`js-digest`, `nextfile-js`)
* Alternative native package manager execution hooks (`bun add`, `yarn add`, `npm install`)
* Arbitrary remote code execution execution pipes (`curl | bash`, `curl | sh`, `curl | node`)

---

## Setup & Installation

Clone the repository directly into your local environment:

```bash
git clone https://github.com/PicasoTheDeal/AUR-threat-mitigator
cd AUR-threat-mitigator
```

## Usage

Execute the auditor directly from your terminal.

[!CAUTION] **Root Privileges Required:** This tool must be executed with `sudo`. The forensic engine requires root access to read protected ALPM metadata directories (`/var/lib/pacman/local/`) and parse restricted system structures without hitting OS permission blocks. Execution will halt immediately if run as an unprivileged user.

```bash
sudo python3 aur-api-audit.py
```

Understanding Diagnostic Verdicts

Green Status: `[CLEAN] Verification complete...`

This means the tool successfully queried the live intelligence feeds (or deployed its fallback validation array), cross-referenced your entire system registry/manifest, scanned all available AUR helper build caches, and found zero matches. Your system does not contain the current targeted supply-chain footprints.

Red Status: `[CRITICAL DISCOVERY] Overlap Found... / [!] DISCOVERY SUMMARY`

This indicates an active indicator of compromise (IoC) or a highly suspicious signature pattern has been located on your local storage drive. The tool will output the exact filepaths along with the specific behavioral signature that triggered the flag.

If this occurs, follow the recommended mitigation checklist printed by the tool:

  1.Purge the package using `pacman -Rns <package-name>`.

  2.Completely wipe out the verified build cache folders under your helper profiles.

  3.Audit active environment storage structures for signs of unauthorized outbound network requests.

  4.Rotate cryptographic keys, access tokens, and sensitive infrastructure session logins immediately.
