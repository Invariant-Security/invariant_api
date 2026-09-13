"""Two independent classifications derived from a Finding's already-known
fields (control_title, document_name, external_id) -- no schema change,
no new Postgres column, nothing invariant_assessment needs to know about.

`classify_domain` groups findings for display (SSH Hardening, Filesystem,
...). A wrong guess here is cosmetic -- keyword matching on the title is
fine.

`classify_environment` decides whether a control is even meaningful
against a Docker container (as opposed to a full Linux host) -- e.g. a
container shares the host kernel, so "is the cramfs kernel module
loaded" reflects the *host's* state, not anything the container itself
controls; it never boots via GRUB; it doesn't run its own NTP daemon.
This feeds directly into the headline "% compliant" number, so it is
NOT keyword matching at runtime -- it's an explicit, hand-reviewed
allowlist of (document_name, external_id) pairs. Getting this wrong
either hides a real finding or manufactures a fake one, either of which
is worse than the "57% compliant" problem this whole module exists to
fix.

HOST_ONLY_CONTROLS was built by querying the controls already ingested
into this appliance's own Postgres (ubuntu_linux_24_04, debian_linux_12,
debian_linux_13 -- the only three documents ingested as of this writing)
for titles matching candidate keywords (kernel module, grub/bootloader,
cron/crontab, firewall/ufw/iptables, timesyncd/chrony/ntp, wireless),
then reviewing every candidate by hand. It is NOT an exhaustive audit of
every one of the ~160 checks -- it's the set that direct evidence (a real
199-control run against real production containers) showed to be
misleading. Extend it the same way (query + manual review) if a new
false FAIL shows up in a container assessment; do not add keywords to a
runtime matcher instead.
"""

from invariant_contracts import Finding

DOMAINS: list[tuple[str, list[str]]] = [
    ("SSH Hardening", ["sshd"]),
    ("Authentication & PAM", ["pam_", "password", "faillock", "pwquality", "pwhistory"]),
    ("Privilege Management", ["sudo", "su ", "root is the only"]),
    ("Audit & Logging", ["audit", "auditd", "aide"]),
    ("Logging", ["journald", "rsyslog", "syslog"]),
    (
        "Filesystem & Permissions",
        ["permissions on", "/etc/shadow", "/etc/passwd", "/etc/group", "world writable", "unowned"],
    ),
    ("Network & Firewall", ["firewall", "iptables", "nftables", "ufw", "ip forwarding", "wireless"]),
    ("Kernel & Boot", ["grub", "bootloader", "kernel module", "single user mode"]),
    ("Scheduled Tasks", ["cron", "crontab", "at.allow", "at.deny"]),
    ("Time Synchronization", ["timesyncd", "chrony", "ntp"]),
]

DOMAIN_NARRATIVE: dict[str, str] = {
    "SSH Hardening": "Multiple SSH security controls are not explicitly configured.",
    "Authentication & PAM": "Password quality and account lockout controls require attention.",
    "Privilege Management": "Sudo hardening and privileged-access logging are incomplete.",
    "Audit & Logging": "Audit rule coverage requires review.",
    "Logging": "Log forwarding/retention configuration requires review.",
    "Filesystem & Permissions": "File and directory permissions do not match the benchmark's expectations.",
    "Network & Firewall": "Network exposure controls are not fully configured.",
    "Kernel & Boot": "Kernel/boot-level hardening controls are incomplete.",
    "Scheduled Tasks": "Scheduled task access controls require review.",
    "Time Synchronization": "Time synchronization is not fully configured.",
    "Other": "Additional controls in this assessment require review.",
}

# (document_name, external_id) -- see module docstring for how this list
# was built and what "reviewed" means here.
HOST_ONLY_CONTROLS: set[tuple[str, str]] = {
    ("debian_linux_12", "1.1.1.1"),
    ("debian_linux_12", "1.1.1.10"),
    ("debian_linux_12", "1.1.1.11"),
    ("debian_linux_12", "1.1.1.2"),
    ("debian_linux_12", "1.1.1.3"),
    ("debian_linux_12", "1.1.1.4"),
    ("debian_linux_12", "1.1.1.5"),
    ("debian_linux_12", "1.1.1.6"),
    ("debian_linux_12", "1.1.1.7"),
    ("debian_linux_12", "1.1.1.8"),
    ("debian_linux_12", "1.1.1.9"),
    ("debian_linux_12", "1.4.1"),
    ("debian_linux_12", "1.4.2"),
    ("debian_linux_12", "2.3.1.1"),
    ("debian_linux_12", "2.3.2.1"),
    ("debian_linux_12", "2.3.2.2"),
    ("debian_linux_12", "2.3.3.1"),
    ("debian_linux_12", "2.3.3.2"),
    ("debian_linux_12", "2.3.3.3"),
    ("debian_linux_12", "2.4.1.1"),
    ("debian_linux_12", "2.4.1.2"),
    ("debian_linux_12", "2.4.1.3"),
    ("debian_linux_12", "2.4.1.4"),
    ("debian_linux_12", "2.4.1.5"),
    ("debian_linux_12", "2.4.1.6"),
    ("debian_linux_12", "2.4.1.7"),
    ("debian_linux_12", "2.4.1.8"),
    ("debian_linux_12", "2.4.1.9"),
    ("debian_linux_12", "3.1.2"),
    ("debian_linux_12", "3.2.1"),
    ("debian_linux_12", "3.2.2"),
    ("debian_linux_12", "3.2.3"),
    ("debian_linux_12", "3.2.4"),
    ("debian_linux_12", "3.2.5"),
    ("debian_linux_12", "3.2.6"),
    ("debian_linux_12", "4.1.1"),
    ("debian_linux_12", "4.1.2"),
    ("debian_linux_12", "4.1.3"),
    ("debian_linux_12", "4.1.4"),
    ("debian_linux_12", "4.1.5"),
    ("debian_linux_12", "6.2.3.28"),
    ("debian_linux_13", "1.1.1.1"),
    ("debian_linux_13", "1.1.1.10"),
    ("debian_linux_13", "1.1.1.11"),
    ("debian_linux_13", "1.1.1.2"),
    ("debian_linux_13", "1.1.1.3"),
    ("debian_linux_13", "1.1.1.4"),
    ("debian_linux_13", "1.1.1.5"),
    ("debian_linux_13", "1.1.1.6"),
    ("debian_linux_13", "1.1.1.7"),
    ("debian_linux_13", "1.1.1.8"),
    ("debian_linux_13", "1.1.1.9"),
    ("debian_linux_13", "1.4.1"),
    ("debian_linux_13", "1.4.2"),
    ("debian_linux_13", "2.3.1.1"),
    ("debian_linux_13", "2.3.2.1"),
    ("debian_linux_13", "2.3.2.2"),
    ("debian_linux_13", "2.3.3.1"),
    ("debian_linux_13", "2.3.3.2"),
    ("debian_linux_13", "2.3.3.3"),
    ("debian_linux_13", "2.4.1.1"),
    ("debian_linux_13", "2.4.1.2"),
    ("debian_linux_13", "2.4.1.3"),
    ("debian_linux_13", "2.4.1.4"),
    ("debian_linux_13", "2.4.1.5"),
    ("debian_linux_13", "2.4.1.6"),
    ("debian_linux_13", "2.4.1.7"),
    ("debian_linux_13", "2.4.1.8"),
    ("debian_linux_13", "2.4.1.9"),
    ("debian_linux_13", "3.1.2"),
    ("debian_linux_13", "3.2.1"),
    ("debian_linux_13", "3.2.2"),
    ("debian_linux_13", "3.2.3"),
    ("debian_linux_13", "3.2.4"),
    ("debian_linux_13", "3.2.5"),
    ("debian_linux_13", "3.2.6"),
    ("debian_linux_13", "3.2.7"),
    ("debian_linux_13", "4.1.1"),
    ("debian_linux_13", "4.1.2"),
    ("debian_linux_13", "4.1.3"),
    ("debian_linux_13", "4.1.4"),
    ("debian_linux_13", "4.1.5"),
    ("debian_linux_13", "6.2.3.31"),
    ("ubuntu_linux_24_04", "1.1.1.1"),
    ("ubuntu_linux_24_04", "1.1.1.10"),
    ("ubuntu_linux_24_04", "1.1.1.11"),
    ("ubuntu_linux_24_04", "1.1.1.2"),
    ("ubuntu_linux_24_04", "1.1.1.3"),
    ("ubuntu_linux_24_04", "1.1.1.4"),
    ("ubuntu_linux_24_04", "1.1.1.5"),
    ("ubuntu_linux_24_04", "1.1.1.6"),
    ("ubuntu_linux_24_04", "1.1.1.7"),
    ("ubuntu_linux_24_04", "1.1.1.8"),
    ("ubuntu_linux_24_04", "1.1.1.9"),
    ("ubuntu_linux_24_04", "1.4.1"),
    ("ubuntu_linux_24_04", "1.4.2"),
    ("ubuntu_linux_24_04", "2.3.1.1"),
    ("ubuntu_linux_24_04", "2.3.2.1"),
    ("ubuntu_linux_24_04", "2.3.2.2"),
    ("ubuntu_linux_24_04", "2.3.3.1"),
    ("ubuntu_linux_24_04", "2.3.3.2"),
    ("ubuntu_linux_24_04", "2.3.3.3"),
    ("ubuntu_linux_24_04", "2.4.1.1"),
    ("ubuntu_linux_24_04", "2.4.1.2"),
    ("ubuntu_linux_24_04", "2.4.1.3"),
    ("ubuntu_linux_24_04", "2.4.1.4"),
    ("ubuntu_linux_24_04", "2.4.1.5"),
    ("ubuntu_linux_24_04", "2.4.1.6"),
    ("ubuntu_linux_24_04", "2.4.1.7"),
    ("ubuntu_linux_24_04", "2.4.1.8"),
    ("ubuntu_linux_24_04", "2.4.1.9"),
    ("ubuntu_linux_24_04", "3.1.2"),
    ("ubuntu_linux_24_04", "3.2.1"),
    ("ubuntu_linux_24_04", "3.2.2"),
    ("ubuntu_linux_24_04", "3.2.3"),
    ("ubuntu_linux_24_04", "3.2.4"),
    ("ubuntu_linux_24_04", "3.2.5"),
    ("ubuntu_linux_24_04", "3.2.6"),
    ("ubuntu_linux_24_04", "4.1.1"),
    ("ubuntu_linux_24_04", "4.1.2"),
    ("ubuntu_linux_24_04", "4.1.3"),
    ("ubuntu_linux_24_04", "4.1.4"),
    ("ubuntu_linux_24_04", "4.1.5"),
    ("ubuntu_linux_24_04", "6.2.3.28"),
}


def classify_domain(control_title: str) -> str:
    lowered = control_title.lower()
    for name, keywords in DOMAINS:
        if any(keyword in lowered for keyword in keywords):
            return name
    return "Other"


def classify_environment(finding: Finding) -> str:
    """Returns "host_only" or "container_relevant". Looked up by
    (document_name, external_id) -- never by title text -- since this
    feeds the headline compliance percentage directly.
    """
    return "host_only" if (finding.document_name, finding.external_id) in HOST_ONLY_CONTROLS else "container_relevant"
