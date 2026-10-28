"""Sysctl parameter security analyzer."""

from __future__ import annotations

from typing import ClassVar

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot


class SysctlAnalyzer(Analyzer):
    """Analyze security-relevant sysctl parameters against hardening baselines."""

    # (sysctl_key, expected_value, finding_id_suffix, title, description, severity, recommendation)
    _CHECKS: ClassVar[
        list[tuple[str, str, str, str, str, Severity, str]]
    ] = [
        (
            "kernel.kptr_restrict",
            "2",
            "KPTR_RESTRICT",
            "Kernel pointer restriction is not fully enabled",
            "kernel.kptr_restrict is not set to 2 (restrict all kernel pointer exposure).",
            Severity.MEDIUM,
            "Set kernel.kptr_restrict=2 to hide kernel symbol addresses from all users.",
        ),
        (
            "kernel.dmesg_restrict",
            "1",
            "DMESG_RESTRICT",
            "Kernel ring buffer readable by unprivileged users",
            "kernel.dmesg_restrict is not set to 1; unprivileged users can read dmesg.",
            Severity.LOW,
            "Set kernel.dmesg_restrict=1 to restrict dmesg to CAP_SYSLOG holders.",
        ),
        (
            "kernel.randomize_va_space",
            "2",
            "ASLR",
            "Full ASLR is not enabled",
            "kernel.randomize_va_space is not set to 2 (full address-space randomisation).",
            Severity.MEDIUM,
            "Set kernel.randomize_va_space=2 to enable full ASLR for stack, heap, and mmap.",
        ),
        (
            "kernel.yama.ptrace_scope",
            "1",
            "PTRACE_SCOPE",
            "Yama ptrace scope is not restricted",
            (
                "kernel.yama.ptrace_scope is 0; any process can ptrace any other "
                "process owned by the same user."
            ),
            Severity.MEDIUM,
            (
                "Set kernel.yama.ptrace_scope=1 to restrict ptrace to direct "
                "parent processes, or higher for stricter isolation."
            ),
        ),
        (
            "net.ipv4.conf.all.rp_filter",
            "1",
            "RP_FILTER",
            "IPv4 reverse-path filtering is disabled",
            (
                "net.ipv4.conf.all.rp_filter is not enabled; spoofed source "
                "addresses may be accepted."
            ),
            Severity.MEDIUM,
            "Set net.ipv4.conf.all.rp_filter=1 to enable strict reverse-path filtering.",
        ),
        (
            "net.ipv4.conf.all.accept_redirects",
            "0",
            "ICMP_REDIRECTS",
            "IPv4 ICMP redirect acceptance is enabled",
            (
                "net.ipv4.conf.all.accept_redirects=1; ICMP redirects can be used "
                "to alter the routing table by an attacker on the same network."
            ),
            Severity.LOW,
            "Set net.ipv4.conf.all.accept_redirects=0 to ignore ICMP redirect messages.",
        ),
        (
            "net.ipv4.tcp_syncookies",
            "1",
            "TCP_SYNCOOKIES",
            "TCP SYN-cookie protection is disabled",
            (
                "net.ipv4.tcp_syncookies is not enabled; the system is susceptible "
                "to TCP SYN-flood denial-of-service attacks."
            ),
            Severity.MEDIUM,
            "Set net.ipv4.tcp_syncookies=1 to mitigate SYN-flood attacks.",
        ),
        (
            "vm.mmap_min_addr",
            "65536",
            "MMAP_MIN_ADDR",
            "mmap minimum address allows NULL-pointer dereference mapping",
            (
                "vm.mmap_min_addr is below 65536; user-space can map the zero page, "
                "enabling kernel NULL-pointer dereference exploits."
            ),
            Severity.HIGH,
            "Set vm.mmap_min_addr=65536 (or higher) to prevent zero-page mappings.",
        ),
    ]

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check sysctl parameters against security hardening baselines."""
        findings: list[Finding] = []

        sysctl_map: dict[str, str] = {}
        for item in snapshot.sysctl_params:
            if item.status.value == "available" and isinstance(item.value, str):
                # Strip the "sysctl." prefix that the collector adds.
                raw_key = item.key.removeprefix("sysctl.")
                sysctl_map[raw_key] = item.value

        for (
            key,
            expected,
            id_suffix,
            title,
            description,
            severity,
            recommendation,
        ) in self._CHECKS:
            actual = sysctl_map.get(key)

            if actual is None:
                # Key not collected or unavailable – skip; avoid false positives.
                continue

            if not self._is_failing(key, actual, expected):
                continue

            findings.append(
                Finding(
                    id=f"KASA-SYSCTL-{id_suffix}",
                    title=title,
                    description=description,
                    severity=severity,
                    category="sysctl-hardening",
                    evidence_keys=[f"sysctl.{key}"],
                    evidence=[
                        FindingEvidence(
                            key=f"sysctl.{key}",
                            value={
                                "key": key,
                                "actual": actual,
                                "expected": expected,
                            },
                        )
                    ],
                    recommendation=recommendation,
                )
            )

        return findings

    @staticmethod
    def _is_failing(key: str, actual: str, expected: str) -> bool:
        """Return True when the actual sysctl value does not meet the baseline."""
        # Special case: vm.mmap_min_addr requires a numeric comparison.
        if key == "vm.mmap_min_addr":
            try:
                return int(actual) < int(expected)
            except ValueError:
                return True

        # For most checks, equality comparison is sufficient.
        return actual != expected
