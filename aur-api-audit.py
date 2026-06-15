import os
import re
import sys
import subprocess
import urllib.request
from pathlib import Path

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
NC = "\033[0m"

ARCH_OFFICIAL_URL = "https://md.archlinux.org/s/SxbqukK6IA/download"
GITHUB_COMMUNITY_URL = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt"

MALICIOUS_SIGNATURES = {
    "lockfile-js": "Known malicious Node downstream payload implant",
    "atomic-lockfile": "Known malicious component footprint",
    "js-digest": "Obfuscated identity harvester string",
    "nextfile-js": "Secondary execution phase delivery token",
    r"npm\s+(install|i)\s+": "Suspicious native Node Package Manager lifecycle execution",
    r"bun\s+add\s+": "Suspicious Bun deployment step inside build lifecycle",
    r"yarn\s+add\s+": "Suspicious Yarn deployment hook detected",
    r"curl\s+.*-s\s+.*\|\s*(bash|sh|node)": "Arbitrary remote code execution pipe pattern"
}

def enforce_root():
    if os.geteuid() != 0:
        print(f"{RED}{BOLD}[!] CRITICAL ERROR: Root privileges required.{NC}")
        print(f"{YELLOW}This forensic tool must be executed with sudo to parse protected system structures.{NC}")
        print(f"Usage: sudo python3 auditor.py\n")
        sys.exit(1)

def print_banner():
    print(f"{CYAN}{BOLD}===================================================================={NC}")
    print(f"{CYAN}{BOLD}        AUR FORENSIC AUDITOR: MULTI-FEED INTELLIGENCE MUX            {NC}")
    print(f"{CYAN}        Parsing Official & Community Open-Source Repositories        {NC}")
    print(f"{CYAN}{BOLD}===================================================================={NC}\n")

def fetch_aggregated_intel():
    compromised_packages = set()
    
    print(f"{BOLD}[*] Attempting Fetch: Official Arch Incident Feed...{NC}")
    req_official = urllib.request.Request(
        ARCH_OFFICIAL_URL, 
        headers={'User-Agent': 'Mozilla/5.0 (X11; Arch Linux; Linux x86_64)'}
    )
    try:
        with urllib.request.urlopen(req_official, timeout=10) as response:
            raw_data = response.read().decode('utf-8')
        for line in raw_data.splitlines():
            line = line.strip()
            match = re.search(r"-\s*([a-zA-Z0-9\-_+\.]+)", line)
            if match and not line.startswith("#"):
                compromised_packages.add(match.group(1).lower())
        print(f"    [SUCCESS] Pulled package definitions from official hedgepad tracker.")
    except Exception as e:
        print(f"    [FAIL] Official feed unreachable: {e}")

    print(f"{BOLD}[*] Attempting Fetch: GitHub Community Consolidated Core Feed...{NC}")
    req_community = urllib.request.Request(
        GITHUB_COMMUNITY_URL, 
        headers={'User-Agent': 'Mozilla/5.0 (X11; Arch Linux; Linux x86_64)'}
    )
    try:
        with urllib.request.urlopen(req_community, timeout=10) as response:
            raw_content = response.read().decode('utf-8')
        for line in raw_content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                compromised_packages.add(line.lower())
        print(f"    [SUCCESS] Merged community definitions from lenucksi tracking repo.")
    except Exception as e:
        print(f"    [FAIL] Community GitHub feed unreachable (Check repo state): {e}")

    if not compromised_packages:
        print(f"    [ALERT] Active multi-feed collection yielded zero results. Deploying fallback validation array.")
        return {"python-plexapi-kanon", "test-malicious-nuke", "test-malicious-reset"}
        
    print(f"    [TOTAL TARGETS] Monitoring {len(compromised_packages)} blacklisted AUR identities across all clusters.")
    return compromised_packages

def parse_local_aur_registry():
    local_registry = {}
    manifest_path = Path("packages.txt")
    
    # Check if local git-tracked manifest file exists (packages.txt containing your list dump)
    if manifest_path.exists():
        print(f"{BOLD}[*] Local manifest file detected ('{manifest_path}'). Loading inventory...{NC}")
        try:
            content = manifest_path.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("```"):
                    fragments = line.split()
                    pkg_name = fragments[0].lower()
                    pkg_version = fragments[1] if len(fragments) > 1 else "manifest-defined"
                    local_registry[pkg_name] = pkg_version
            print(f"    [SUCCESS] Loaded {len(local_registry)} package definitions out of local manifest tracking.")
            return local_registry
        except Exception as e:
            print(f"    [ERROR] Failed to read local file configuration: {e}")

    print(f"{BOLD}[*] No local tracking file found. Interrogating local ALPM subsystem...{NC}")
    try:
        res = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            fragments = line.strip().split()
            if len(fragments) == 2:
                local_registry[fragments[0].lower()] = fragments[1]
        print(f"    [SUCCESS] Extracted {len(local_registry)} locally installed custom packages.")
        return local_registry
    except FileNotFoundError:
        print(f"    [WARN] pacman environment layer missing and no local manifest file provided.")
        return {}
    except Exception as e:
        print(f"    [ERROR] Failed to map system package tables: {e}")
        return {}

def analyze_pkgbuild_content(file_path):
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for signature, description in MALICIOUS_SIGNATURES.items():
            if re.search(signature, content, re.IGNORECASE):
                findings.append((signature, description))
    except PermissionError:
        pass
    except Exception:
        pass
    return findings

def deep_scan_all_caches(user_home):
    """ Sweeps every folder inside all local caches for zero-day signature patterns, regardless of blacklists """
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
            print(f"    [-] Cache path not found or empty: {base}")
            continue
            
        print(f"    {BOLD}[*] Deep parsing cache root tree: {base}{NC}")
        for pkgbuild_file in base.glob("**/PKGBUILD"):
            total_scanned += 1
            structural_anomalies = analyze_pkgbuild_content(pkgbuild_file)
            if structural_anomalies:
                total_hits += 1
                deep_compromised = True
                print(f"\n      {RED}{BOLD}[CRITICAL CONTENT ALERT] Malicious footprint caught in non-indexed cache profile!{NC}")
                print(f"      Filepath: {pkgbuild_file}")
                for sig, desc in structural_anomalies:
                    print(f"        [-] Triggered Pattern Match: '{sig}' -> ({desc})")
                    
    print(f"\n    [COMPLETE] Deep forensic sweep complete. Analyzed {total_scanned} total cache script structures. Found {total_hits} anomalies.")
    return deep_compromised

def audit_target_locations(package, version, user_home):
    print(f"\n{RED}{BOLD}[CRITICAL DISCOVERY] Overlap Found with Threat Target: '{package}' (Version: {version}){NC}")
    print(f"  {MAGENTA}{UNDERLINE}Targeted Forensic Investigation & Filepath Validation:{NC}")
    
    threat_isolated = False
    
    alpm_meta_base = Path(f"/var/lib/pacman/local/{package}-{version}")
    print(f"    {BOLD}[*] Checking ALPM Structural Metadata Directory:{NC}")
    if alpm_meta_base.exists():
        threat_isolated = True
        print(f"      [FOUND LIVE ON DISK] -> {alpm_meta_base}")
        for critical_file in ["desc", "files", "install"]:
            target_file = alpm_meta_base / critical_file
            if target_file.exists():
                print(f"        [-] File verified: {target_file}")
                if critical_file in ["desc", "install"]:
                    anomalies = analyze_pkgbuild_content(target_file)
                    for sig, desc in anomalies:
                        print(f"          [BEHAVIORAL HIT] Script footprint detected: '{sig}' -> ({desc})")
    else:
        print(f"      [NOT PRESENT] No registered system installation path at: {alpm_meta_base}")

    cache_clusters = [
        user_home / f".cache/yay/{package}",
        user_home / f".cache/paru/{package}",
        user_home / f".cache/aurutils/sync/{package}",
        Path(f"/var/cache/aur/{package}")
    ]
    
    print(f"    {BOLD}[*] Mapping Explicit Helper Cache Target Folders:{NC}")
    for cache_directory in cache_clusters:
        if cache_directory.exists():
            threat_isolated = True
            print(f"      [FOUND CACHED SOURCE] -> {cache_directory}")
            
            pkgbuild_file = cache_directory / "PKGBUILD"
            if pkgbuild_file.exists():
                print(f"        [-] Target File Found: {pkgbuild_file}")
                structural_anomalies = analyze_pkgbuild_content(pkgbuild_file)
                if structural_anomalies:
                    print(f"          [CRITICAL CONTENT ALERT] Malicious logic identified inside this PKGBUILD:")
                    for sig, desc in structural_anomalies:
                        print(f"            [-] Found String: '{sig}' -> Description: {desc}")
                else:
                    print(f"          [CLEAN] Target PKGBUILD clear of known behavioral infection strings.")
        else:
            print(f"      [CLEAN] No tracking structure found at: {cache_directory}")
            
    if not threat_isolated and version == "manifest-defined":
        print(f"      [MANIFEST WARNING] Package identity found in tracking index list, but no historical build directory was located on disk profiles.")
        threat_isolated = True
        
    return threat_isolated

def main():
    enforce_root()
    print_banner()
    
    # Safely step back to target user's home layout despite execution via sudo
    sudo_user = os.environ.get("SUDO_USER")
    user_home = Path(f"/home/{sudo_user}") if sudo_user else Path.home()
    
    threat_feed = fetch_aggregated_intel()
    local_packages = parse_local_aur_registry()
    
    system_compromised = False

    if local_packages:
        print(f"\n{BOLD}[*] Cross-referencing manifest targets against tracking feeds...{NC}")
        compromised_intersections = set(local_packages.keys()).intersection(threat_feed)
        
        if compromised_intersections:
            for package_match in compromised_intersections:
                hit_status = audit_target_locations(package_match, local_packages[package_match], user_home)
                if hit_status:
                    system_compromised = True

    # Run unrestricted deep parsing loop over every cached script file across storage
    deep_hit_status = deep_scan_all_caches(user_home)
    if deep_hit_status:
        system_compromised = True
    
    print(f"\n{BOLD}============================== Diagnostic Verdict =============================={NC}")
    
    if system_compromised:
        print(f"\n{RED}{BOLD}[!] DISCOVERY SUMMARY: SYSTEM COMPROMISE OR SUSPICIOUS CONTENT LOGGED [!]{NC}")
        print(f"{RED}The forensic analysis engine identified matched indicators of threat actions on local data layers.{NC}")
        print(f"\n{YELLOW}{BOLD}Recommended Threat Mitigation Checklist:{NC}")
        print(f"  1. Purge targeted packages using: pacman -Rns <package-name>")
        print(f"  2. Completely wipe out the verified build cache folders under your helper profiles.")
        print(f"  3. Audit active environment storage structures for signs of suspicious outbound network requests.")
        print(f"  4. Rotate cryptographic keys, access tokens, and infrastructure session logins immediately.")
    else:
        print(f"{GREEN}[CLEAN] Verification complete. Installed targets match the baseline and all deep script verification signatures passed clean.{NC}")
        
    print(f"{BOLD}================================================================================{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[-] Execution halted cleanly via user break signal.{NC}")
        sys.exit(0)
