import os
import re
import sys
import subprocess
from pathlib import Path

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
NC = "\033[0m"

MALICIOUS_SIGNATURES = {
    "lockfile-js": "Known Node payload implant",
    "atomic-lockfile": "Known component footprint",
    r"npm\s+(install|i)\s+": "Suspicious native Node Package Manager execution",
    r"curl\s+.*-s\s+.*\|\s*(bash|sh|node)": "Arbitrary remote code execution pipe",
    r"wget\s+.*-qO-\s+.*\|\s*(bash|sh)": "Arbitrary remote code execution pipe via wget",
    r"base64\s+-d\s*\|\s*(bash|sh)": "Obfuscated Base64 execution pipe",
    r"eval\s*\(\s*curl": "Eval injection via web request",
    r"exec\s+3<>/dev/tcp/": "Direct bash reverse shell / TCP socket opening",
    r"\\x[0-9a-fA-F]{2}": "Hex-encoded payload string detected"
}

def print_banner():
    print(f"{CYAN}{BOLD}===================================================================={NC}")
    print(f"{CYAN}{BOLD}        AUR FORENSIC AUDITOR: LOCAL OFFLINE ENGINE                  {NC}")
    print(f"{CYAN}        Zero Network Footprint — Relying on Council Manifest        {NC}")
    print(f"{CYAN}{BOLD}===================================================================={NC}\n")

def load_local_manifest():
    manifest_path = Path("packages.txt")
    compromised_packages = set()
    
    if not manifest_path.exists():
        print(f"{RED}[!] FATAL: 'packages.txt' not found in current directory.{NC}")
        print(f"{YELLOW}Please ensure you have pulled the latest validated manifest from the repo.{NC}")
        sys.exit(1)
        
    print(f"{BOLD}[*] Loading council-approved local manifest '{manifest_path}'...{NC}")
    try:
        content = manifest_path.read_text(errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and re.match(r"^[a-z0-9\-_\+\.]+$", line):
                compromised_packages.add(line)
        print(f"    [SUCCESS] Loaded {len(compromised_packages)} blacklisted signatures securely.")
        return compromised_packages
    except Exception as e:
        print(f"{RED}[!] Error parsing local manifest tracking table: {e}{NC}")
        sys.exit(1)

def parse_local_aur_registry():
    local_registry = {}
    print(f"{BOLD}[*] Interrogating local ALPM database via pacman...{NC}")
    try:
        res = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            fragments = line.strip().split()
            if len(fragments) == 2:
                local_registry[fragments[0].lower()] = fragments[1]
        print(f"    [SUCCESS] Mapped {len(local_registry)} foreign/AUR packages currently installed.")
        return local_registry
    except FileNotFoundError:
        print(f"{YELLOW}[!] pacman binary not found. Are you running this on an Arch-based system?{NC}")
        return {}
    except Exception as e:
        print(f"    [ERROR] Failed to map local system package tables: {e}")
        return {}

def analyze_pkgbuild_content(file_path):
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for signature, description in MALICIOUS_SIGNATURES.items():
            if re.search(signature, content, re.IGNORECASE):
                findings.append((signature, description))
    except Exception:
        pass
    return findings

def deep_scan_all_caches(user_home):
    print(f"\n{CYAN}{BOLD}[*] Launching Unrestricted Deep PKGBUILD Content Signature Sweep...{NC}")
    cache_bases = [
        user_home / ".cache/yay",
        user_home / ".cache/paru",
        user_home / ".cache/aurutils/sync",
        Path("/var/cache/aur")
    ]
    
    total_scanned = 0
    total_hits = 0
    deep_compromised = False
    
    for base in cache_bases:
        if not base.exists():
            continue
        print(f"    {BOLD}[*] Deep parsing cache root tree: {base}{NC}")
        for pkgbuild_file in base.glob("**/PKGBUILD"):
            total_scanned += 1
            structural_anomalies = analyze_pkgbuild_content(pkgbuild_file)
            if structural_anomalies:
                total_hits += 1
                deep_compromised = True
                print(f"\n      {RED}{BOLD}[CRITICAL CONTENT ALERT] Malicious footprint caught in build cache!{NC}")
                print(f"      Filepath: {pkgbuild_file}")
                for sig, desc in structural_anomalies:
                    print(f"        [-] Triggered Heuristic Match: '{sig}' -> ({desc})")
                    
    print(f"\n    [COMPLETE] Deep forensic sweep complete. Analyzed {total_scanned} build scripts. Found {total_hits} anomalies.")
    return deep_compromised

def audit_target_locations(package, version, user_home):
    print(f"\n{RED}{BOLD}[CRITICAL DISCOVERY] Overlap Found with Known Malicious Target: '{package}' (Version: {version}){NC}")
    threat_isolated = False
    
    alpm_meta_base = Path(f"/var/lib/pacman/local/{package}-{version}")
    if alpm_meta_base.exists():
        threat_isolated = True
        print(f"    {BOLD}[*] ALPM Database Entry Verified:{NC} {alpm_meta_base}")
        for critical_file in ["desc", "install"]:
            target_file = alpm_meta_base / critical_file
            if target_file.exists():
                structural_anomalies = analyze_pkgbuild_content(target_file)
                for sig, desc in structural_anomalies:
                    print(f"        [BEHAVIORAL HIT] Metadata anomaly detected: '{sig}' -> ({desc})")

    cache_clusters = [
        user_home / f".cache/yay/{package}",
        user_home / f".cache/paru/{package}",
        user_home / f".cache/aurutils/sync/{package}",
        Path(f"/var/cache/aur/{package}")
    ]
    
    for cache_directory in cache_clusters:
        if cache_directory.exists():
            threat_isolated = True
            print(f"    {BOLD}[*] Found Local Cached Source Layout:{NC} {cache_directory}")
            pkgbuild_file = cache_directory / "PKGBUILD"
            if pkgbuild_file.exists():
                structural_anomalies = analyze_pkgbuild_content(pkgbuild_file)
                for sig, desc in structural_anomalies:
                    print(f"        [CRITICAL CONTENT ALERT] Malicious logic verified in PKGBUILD: '{sig}' -> ({desc})")
                    
        return threat_isolated

def main():
    print_banner()
    
    user_home = Path.home()
    
    threat_feed = load_local_manifest()
    local_packages = parse_local_aur_registry()
    system_compromised = False

    if local_packages:
        print(f"\n{BOLD}[*] Cross-referencing installed environment against local manifest...{NC}")
        compromised_intersections = set(local_packages.keys()).intersection(threat_feed)
        
        if compromised_intersections:
            for package_match in compromised_intersections:
                if audit_target_locations(package_match, local_packages[package_match], user_home):
                    system_compromised = True

    if deep_scan_all_caches(user_home):
        system_compromised = True
    
    print(f"\n{BOLD}============================== Diagnostic Verdict =============================={NC}")
    
    if system_compromised:
        print(f"\n{RED}{BOLD}[!] DISCOVERY SUMMARY: SUSPICIOUS ACTIVITY OR COMPROMISED PKGBUILD DETECTED [!]{NC}")
        print(f"{RED}The host machine has trace indicators matching the AUR threat profiles.{NC}")
        print(f"\n{YELLOW}{BOLD}Post-Exploitation Incident Response Checklist:{NC}")
        print(f"  1. Isolate this machine from your local network immediately.")
        print(f"  2. Do NOT trust a simple uninstall via pacman. Malicious code may have executed.")
        print(f"  3. Audit '~/.config/systemd/user/' and '/etc/systemd/system/' for rogue timers/services.")
        print(f"  4. Check user profile files ('~/.bashrc', '~/.zshrc') for persistent telemetry loops.")
        print(f"  5. Inspect temporary runtime layouts like /tmp/ and /dev/shm/ for dropped binaries.")
        print(f"  6. Terminate existing sessions and rotate cryptographic keys/tokens from a clean machine.")
    else:
        print(f"{GREEN}[CLEAN] Verification complete. Local foreign structures match baseline safety protocols.{NC}")
        
    print(f"{BOLD}================================================================================{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
