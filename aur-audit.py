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
    ("base64\\s+-(d|-decode)", "Base64 Decoding: hidden payloads in memory"),
    ("openssl\\s+enc\\s+-base64", "Alternative Base64 Decoding: Using OpenSSL to decode hidden data"),
    ("\\\\[xX][0-9a-fA-F]{2}", "Hex Escaping: Hiding malicious strings past basic keyword filters"),
    ("\\\\[0-7]{3}", "Octal Escaping: Masking text to trick signature scanners"),
    ("c['\"\\\\\\\\']*u['\"\\\\\\\\']*r['\"\\\\\\\\']*l", "Obfuscated curl: Hiding data-transfer commands to bypass filters"),
    ("w['\"\\\\\\\\']*g['\"\\\\\\\\']*e['\"\\\\\\\\']*t", "Obfuscated wget: Hiding external file download commands"),
    ("n['\"\\\\\\\\']*p['\"\\\\\\\\']*m(?:\\\\\\\\?\\s)+(install|i)", "Obfuscated npm install: Hiding Node package installations"),
    ("y['\"\\\\\\\\']*a['\"\\\\\\\\']*r['\"\\\\\\\\']*n(?:\\\\\\\\?\\s)+install", "Obfuscated yarn install: Hiding Yarn package manager installations"),
    ("p['\"\\\\\\\\']*n['\"\\\\\\\\']*p['\"\\\\\\\\']*m(?:\\\\\\\\?\\s)+install", "Obfuscated pnpm install: Hiding pnpm package manager installations"),
    ("lockfile-js", "Lockfile Dependency Check: Checking for JS lockfiles, often for supply-chain poisoning"),
    ("atomic-lockfile", "Atomic Lockfile Check: Associated with automated supply-chain manipulation"),
    ("(socat|nc|netcat)\\s+", "Netcat/Socat Usage: Spawning unencrypted reverse shells"),
    ("exec\\s+\\d+<>/dev/(tcp|udp)", "Bash Native Reverse Shell: Backdoor routing natively through Bash networking"),
    ("eval\\s*\\(", "Dynamic Code Execution: Running downloaded/decoded text as live code"),
    ("(md5|sha256)sums\\s*=\\s*\\([^\\)]*['\"]SKIP['\"]", "Checksum Bypassing: Skipping file integrity verification in build scripts"),
    ("source\\s*=\\s*\\([^\\)]*git\\+sys:", "Sketchy Build Sources: Unusual custom protocols indicating hijacked downloads"),
    ("chmod\\s+(\\+s|4[0-7]{3})", "SUID Backdoor Creation: Setting files to execute with root privileges"),
    ("chown\\s+root", "Root Ownership Assignment: Transferring file ownership to root for backdoors"),
    ("NOPASSWD\\s*:\\s*ALL", "Sudoers Exploitation: Allowing a user to run root commands without a password"),
    ("pkexec\\s+", "Polkit Execution: Potential local privilege escalation via PolicyKit"),
    ("LD_PRELOAD=", "Environment Hijacking: Pre-loading custom libraries to hook/hijack system functions"),
    ("systemctl\\s+(enable|stop)", "Service Tampering: Auto-starting backdoors or stopping security services"),
    ("crontab\\s+", "Scheduled Task Persistence: Tampering with cron jobs to repeatedly execute malware"),
    ("/etc/(sudoers|passwd|rc\\.local|systemd|cron)", "Core System File Tampering: Modifying critical authentication/startup files"),
    ("\\.config/autostart", "Desktop Auto-Start: Dropping malware to launch on graphical desktop login"),
    ("\\.(bashrc|zshrc|profile|bash_profile)", "Shell Profile Poisoning: Injecting malicious commands into user terminal startup"),
    ("setenforce\\s+0", "Disabling SELinux: Turning off mandatory access controls"),
    ("rm\\s+-rf\\s+/var/log", "Log Nuking: Aggressively deleting system logs to destroy evidence"),
    ("unset\\s+HISTFILE", "Killing History Logging: Telling the shell to stop saving command history"),
    ("HISTSIZE=0", "Disabling History: Setting terminal history size to zero"),
    ("history\\s+-c", "Clearing Evidence: Wiping current shell history buffer"),
    ("\\.(aws/credentials|kube/config|docker/config\\.json|ssh/id_)", "Secret Hunting: Targeting cloud, container, or SSH credentials"),
    ("discord(app)?\\.com/api/webhooks", "Discord Data Exfiltration: Using webhooks to dump stolen data"),
    ("api\\.telegram\\.org/bot", "Telegram Data Exfiltration: Using Telegram bots for command-and-control/data leaks"),
    ("pastebin\\.com/raw", "Payload Fetching: Downloading malicious code staging snippets"),
    ("curl\\s+.*-F\\s+['\"]file=@", "File Uploading via Curl: Actively packaging and uploading local files")
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
        for signature, explanation in MALICIOUS_SIGNATURES:
            if re.search(signature, content, re.IGNORECASE):
                findings.append((signature, explanation))
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
            for sig, explanation in structural_anomalies:
                findings_list.append(f"{pkgbuild_file}: Trigger '{sig}'\n    -> Reason: {explanation}")
    return findings_list

def audit_target_locations(package, version, user_home):
    findings_list = []
    alpm_meta_base = Path(f"/var/lib/pacman/local/{package}-{version}")
    if alpm_meta_base.exists():
        for critical_file in ["desc", "install"]:
            target_file = alpm_meta_base / critical_file
            if target_file.exists():
                structural_anomalies = analyze_file_content(target_file)
                for sig, explanation in structural_anomalies:
                    findings_list.append(f"{target_file}: Trigger '{sig}'\n    -> Reason: {explanation}")

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
                for sig, explanation in structural_anomalies:
                    findings_list.append(f"{pkgbuild_file}: Trigger '{sig}'\n    -> Reason: {explanation}")
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
