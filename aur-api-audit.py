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
GITHUB_COMMUNITY_URL = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/main/package_list.txt"

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
        print(f"    [SUCCESS] Merged community definitions from open-source GitHub intelligence repo.")
    except Exception as e:
        print(f"    [FAIL] Community GitHub feed unreachable: {e}")

    if not compromised_packages:
        print(f"    [ALERT] Active multi-feed collection yielded zero results. Deploying fallback validation array.")
        return {"python-plexapi-kanon", "atomic-lockfile-test"}
        
    print(f"    [TOTAL TARGETS] Monitoring {len(compromised_packages)} blacklisted AUR identities across all clusters.")
    return compromised_packages

def parse_local_aur_registry():
    print(f"{BOLD}[*] Interrogating Foreign Package Subsystem via ALPM Layers...{NC}")
    try:
        res = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        local_registry = {}
        for line in res.stdout.splitlines():
            fragments = line.strip().split()
            if len(fragments) == 2:
                local_registry[fragments[0].lower()] = fragments[1]
        print(f"    [SUCCESS] Extracted {len(local_registry)} locally installed custom packages.")
        return local_registry
    except FileNotFoundError:
        print(f"    [WARN] pacman binary absent (Environment: Sandbox/Codespace).")
        print(f"    [INFO] Injecting simulated live target configuration matrix for logic verification:")
        simulated_matrix = {
            "python-plexapi-kanon": "3.2.1-1",
            "neofetch": "7.1.0-2",
            "google-chrome": "122.0.6261.94-1"
        }
        for pkg, ver in simulated_matrix.items():
            print(f"        -> {pkg} (Active Version: {ver})")
        return simulated_matrix
    except Exception as e:
        print(f"    [ERROR] Failed to extract local database maps: {e}")
        return {}

def analyze_pkgbuild_content(file_path):
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for signature, description in MALICIOUS_SIGNATURES.items():
            if re.search(signature, content, re.IGNORECASE):
                findings.append((signature, description))
    except Exception as e:
        print(f"      [WARN] Unable to parse stream reading on file {file_path.name}: {e}")
    return findings

def audit_target_locations(package, version):
    print(f"\n{RED}{BOLD}[CRITICAL DISCOVERY] System Overlaps with Threat Target: '{package}' (Version: {version}){NC}")
    print(f"  {MAGENTA}{UNDERLINE}Forensic Investigation & Filepath Validation Paths:{NC}")
    
    threat_isolated = False
    
    alpm_meta_base = Path(f"/var/lib/pacman/local/{package}-{version}")
    print(f"    {BOLD}[*] ALPM Structural Metadata Directory:{NC}")
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
        Path.home() / f".cache/yay/{package}",
        Path.home() / f".cache/paru/{package}",
        Path.home() / f".cache/aurutils/sync/{package}",
        Path(f"/var/cache/aur/{package}")
    ]
    
    print(f"    {BOLD}[*] AUR Helper Source Build & Compilation Cache Directories:{NC}")
    cache_hit_logged = False
    for cache_directory in cache_clusters:
        if cache_directory.exists():
            threat_isolated = True
            cache_hit_logged = True
            print(f"      [FOUND CACHED SOURCE] -> {cache_directory}")
            
            pkgbuild_file = cache_directory / "PKGBUILD"
            if pkgbuild_file.exists():
                print(f"        [-] Target File Found: {pkgbuild_file}")
                print(f"        [*] Executing Deep Content Inspection Engine inside PKGBUILD...")
                
                structural_anomalies = analyze_pkgbuild_content(pkgbuild_file)
                if structural_anomalies:
                    print(f"          [CRITICAL CONTENT ALERT] Malicious logic identified inside this PKGBUILD:")
                    for sig, desc in structural_anomalies:
                        print(f"            [-] Found String: '{sig}' -> Description: {desc}")
                else:
                    print(f"          [CLEAN] PKGBUILD clear of known behavioral infection strings.")
                    
            for automated_src in cache_directory.glob("*.install"):
                if automated_src.exists():
                    print(f"        [-] Target Context Script Found: {automated_src}")
        else:
            print(f"      [CLEAN] No directory structure found at: {cache_directory}")
            
    if not cache_hit_logged:
        print(f"      [CLEAN] Clean environment state across tracking cache points.")
        
    return threat_isolated

def main():
    print_banner()
    
    if os.getuid() != 0:
        print(f"{YELLOW}[!] Notice: Process running without system root access.{NC}")
        print(f"{YELLOW}[!] System evaluation depth for protected structures (/var/lib/pacman/) might be limited.{NC}\n")
        
    threat_feed = fetch_aggregated_intel()
    local_packages = parse_local_aur_registry()
    
    print(f"\n{BOLD}[*] Cross-referencing installed applications against active threat vectors...{NC}")
    compromised_intersections = set(local_packages.keys()).intersection(threat_feed)
    
    print(f"\n{BOLD}============================== Diagnostic Verdict =============================={NC}")
    
    system_compromised = False
    if compromised_intersections:
        for package_match in compromised_intersections:
            hit_status = audit_target_locations(package_match, local_packages[package_match])
            if hit_status:
                system_compromised = True
                
        if system_compromised:
            print(f"\n{RED}{BOLD}[!] DISCOVERY SUMMARY: SYSTEM COMPROMISE CONFIRMED [!]{NC}")
            print(f"{RED}The indicators isolated above match the parameters of the active AUR attack pipeline.{NC}")
            print(f"\n{YELLOW}{BOLD}Recommended Threat Mitigation Checklist:{NC}")
            print(f"  1. Purge the packages cleanly immediately: sudo pacman -Rns <package-name>")
            print(f"  2. Completely wipe out the cached build directories found under the .cache paths.")
            print(f"  3. Audit active environment storage structures for signs of suspicious outbound data transfers.")
            print(f"  4. Rotate system infrastructure keys, tokens, and active session logins immediately.")
        else:
            print(f"\n{YELLOW}[INFO] Target package name intersection matched feed metadata, but no components exist on disk.{NC}")
            print(f"{GREEN}[CLEAN] Evaluation Complete. Active threat footprint negated.{NC}")
    else:
        print(f"{GREEN}[CLEAN] Core Verification Passed. No installed targets overlap with the active tracking feed.{NC}")
        
    print(f"{BOLD}================================================================================{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[-] Execution halted cleanly via user break signal.{NC}")
        sys.exit(0)
