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

### 2. Local ALPM Interrogation
Instead of checking what's currently online, the script taps directly into the local Arch Linux Package Management (ALPM) subsystem. It queries the local package registry located at `/var/lib/pacman/local/`, extracting metadata from the `desc` and `install` files of foreign packages (`pacman -Qm`) to check if a compromised package version was compiled and registered on the host system before the upstream purge occurred.

### 3. Deep Cache Scanning & Regex Matching
Even if a package was partially removed or failed during build, AUR helpers leave historical build directories on disk. The tool hunts down compilation footprints across the most common AUR helper ecosystems:
* `yay` (`~/.cache/yay/`)
* `paru` (`~/.cache/paru/`)
* `aurutils` (`~/.cache/aurutils/sync/` & `/var/cache/aur/`)

It opens cached `PKGBUILD` and `.install` files, passing their contents through a regex signature engine looking for specific malicious footprints, obfuscated identity harvesters, and arbitrary code execution pipe patterns (like `curl | bash` or native package manager lifecycle execution hooks).

---

## Setup & Installation

Clone the repository directly into your local environment:

```bash
git clone [https://github.com/PicasoTheDeal/AUR-threat-mitigator](https://github.com/PicasoTheDeal/AUR-threat-mitigator)
cd AUR-threat-mitigator
```

---

## Usage

Execute the auditor directly from your terminal. 

*Note: Running the script with root privileges (`sudo`) is highly recommended. While the script does not alter system configurations, root access ensures the forensic engine can read protected ALPM metadata directories (`/var/lib/pacman/local/`) without getting hit by OS permission blocks.*

```bash
python3 auditor.py
```

---

## Understanding Diagnostic Verdicts

### Green Status: `[CLEAN] Core Verification Passed`
This means the tool successfully queried the live intelligence feeds, cross-referenced your entire system registry, scanned all available AUR helper build caches, and found zero matches. Your system does not contain the current targeted supply-chain footprints.

### Red Status: `[CRITICAL DISCOVERY] System Overlaps with Threat Target`
This indicates an active indicator of compromise (IoC) has been located on your local storage drive. The tool will output the exact filepaths (`/var/lib/pacman/local/...` or `~/.cache/...`) along with the specific behavioral signature that triggered the flag. 

If this occurs, follow the recommended mitigation checklist printed by the tool: purge the package using `pacman -Rns`, completely wipe out the matching cache directories, audit active storage for unauthorized outbound connections, and rotate sensitive local session tokens/keys immediately.
