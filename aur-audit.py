#!/usr/bin/env python3
import os
import re
import sys
import subprocess
from pathlib import Path

RED = "\033[1;31m"
GREEN = "\033[1;32m"
NC = "\033[0m"

MANIFEST_FILE = "packages.txt"

MALICIOUS_SIGNATURES = [
    "base64\\s+-(d|-decode)",
    "openssl\\s+enc\\s+-base64",
    "\\\\[xX][0-9a-fA-F]{2}",
    "\\\\[0-7]{3}",
    "c['\"\\\\\\\\']*u['\"\\\\\\\\']*r['\"\\\\\\\\']*l",
    "w['\"\\\\\\\\']*g['\"\\\\\\\\']*e['\"\\\\\\\\']*t",
    "n['\"\\\\\\\\']*p['\"\\\\\\\\']*m(?:\\\\\\\\?\\s)+(install|i)",
    "y['\"\\\\\\\\']*a['\"\\\\\\\\']*r['\"\\\\\\\\']*n(?:\\\\\\\\?\\s)+install",
    "p['\"\\\\\\\\']*n['\"\\\\\\\\']*p['\"\\\\\\\\']*m(?:\\\\\\\\?\\s)+install",
    "lockfile-js",
    "atomic-lockfile",
    "(socat|nc|netcat)\\s+",
    "exec\\s+\\d+<>/dev/(tcp|udp)",
    "eval\\s*\\(",
    "(md5|sha256)sums\\s*=\\s*\\([^\\)]*['\"]SKIP['\"]",
    "source\\s*=\\s*\\([^\\)]*git\\+sys:",
    "chmod\\s+(\\+s|4[0-7]{3})",
    "chown\\s+root",
    "NOPASSWD\\s*:\\s*ALL",
    "pkexec\\s+",
    "LD_PRELOAD=",
    "systemctl\\s+(enable|stop)",
    "crontab\\s+",
    "/etc/(sudoers|passwd|rc\\.local|systemd|cron)",
    "\\.config/autostart",
    "\\.(bashrc|zshrc|profile|bash_profile)",
    "setenforce\\s+0",
    "rm\\s+-rf\\s+/var/log",
    "unset\\s+HISTFILE",
    "HISTSIZE=0",
    "history\\s+-c",
    "\\.(aws/credentials|kube/config|docker/config\\.json|ssh/id_)",
    "discord(app)?\\.com/api/webhooks",
    "api\\.telegram\\.org/bot",
    "pastebin\\.com/raw",
    "curl\\s+.*-F\\s+['\"]file=@"
]

def load_local_manifest():
    manifest_path = Path(MANIFEST_FILE)
    compromised_packages = set()
    if not manifest_path.exists():
        sys.exit(1)
    try:
        content = manifest_path.read_text(errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and re.match(r"^[a-z0-9\-_\+\.]+$", line):
                compromised_packages.add(line.lower())
        return compromised_packages
    except Exception:
        sys.exit(1)

def parse_local_aur_registry():
    local_registry = {}
    try:
        res = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            fragments = line.strip().split()
            if len(fragments) == 2:
                local_registry[fragments[0].lower()] = fragments[1]
        return local_registry
    except Exception:
        return {}

def analyze_file_content(file_path):
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for signature in MALICIOUS_SIGNATURES:
            if re.search(signature, content, re.IGNORECASE):
                findings.append(signature)
    except Exception:
        pass
    return findings

def deep_scan_all_caches(user_home):
    cache_bases = [
        user_home / ".cache/yay",
        user_home / ".cache/paru",
        user_home / ".cache/aurutils/sync",
        Path("/var/cache/aur")
    ]
    findings_list = []
    for base in cache_bases:
        if not base.exists():
            continue
        for pkgbuild_file in base.glob("**/PKGBUILD"):
            structural_anomalies = analyze_file_content(pkgbuild_file)
            for sig in structural_anomalies:
                findings_list.append(f"{pkgbuild_file}: Trigger '{sig}'")
    return findings_list

def audit_target_locations(package, version, user_home):
    findings_list = []
    alpm_meta_base = Path(f"/var/lib/pacman/local/{package}-{version}")
    if alpm_meta_base.exists():
        for critical_file in ["desc", "install"]:
            target_file = alpm_meta_base / critical_file
            if target_file.exists():
                structural_anomalies = analyze_file_content(target_file)
                for sig in structural_anomalies:
                    findings_list.append(f"{target_file}: Trigger '{sig}'")

    cache_clusters = [
        user_home / f".cache/yay/{package}",
        user_home / f".cache/paru/{package}",
        user_home / f".cache/aurutils/sync/{package}",
        Path(f"/var/cache/aur/{package}")
    ]
    for cache_directory in cache_clusters:
        if cache_directory.exists():
            pkgbuild_file = cache_directory / "PKGBUILD"
            if pkgbuild_file.exists():
                structural_anomalies = analyze_file_content(pkgbuild_file)
                for sig in structural_anomalies:
                    findings_list.append(f"{pkgbuild_file}: Trigger '{sig}'")
    return findings_list

def main():
    user_home = Path.home()
    threat_feed = load_local_manifest()
    local_packages = parse_local_aur_registry()
    all_findings = []

    if local_packages:
        compromised_intersections = set(local_packages.keys()).intersection(threat_feed)
        for package_match in compromised_intersections:
            all_findings.extend(audit_target_locations(package_match, local_packages[package_match], user_home))

    all_findings.extend(deep_scan_all_caches(user_home))

    if all_findings:
        for finding in set(all_findings):
            print(f"{RED}[!] {finding}{NC}")
        sys.exit(1)
    else:
        print(f"{GREEN}[+] Found nothing{NC}")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
