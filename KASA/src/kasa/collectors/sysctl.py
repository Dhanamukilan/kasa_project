"""Linux sysctl parameter collector."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from kasa.models.evidence import EvidenceItem, EvidenceSource, EvidenceStatus


# Security-relevant sysctl keys to collect, grouped by category.
_SECURITY_SYSCTLS: list[tuple[str, str]] = [
    # Kernel self-protection
    ("kernel.kptr_restrict", "Restrict kernel pointer exposure in /proc"),
    ("kernel.dmesg_restrict", "Restrict dmesg access to privileged users"),
    ("kernel.perf_event_paranoid", "Restrict perf subsystem access"),
    ("kernel.randomize_va_space", "Address space layout randomisation (ASLR) level"),
    ("kernel.yama.ptrace_scope", "Yama LSM ptrace scope restriction"),
    ("kernel.unprivileged_bpf_disabled", "Restrict BPF usage to privileged users"),
    ("kernel.kexec_load_disabled", "Prevent loading a new kernel via kexec"),
    ("kernel.sysrq", "Magic SysRq key access level"),
    # Network hardening
    ("net.ipv4.conf.all.rp_filter", "IPv4 reverse-path filter (all interfaces)"),
    ("net.ipv4.conf.default.rp_filter", "IPv4 reverse-path filter (new interfaces)"),
    ("net.ipv4.conf.all.accept_redirects", "Ignore IPv4 ICMP redirect acceptance"),
    ("net.ipv4.conf.default.accept_redirects", "Ignore IPv4 redirect (default)"),
    ("net.ipv4.conf.all.secure_redirects", "Restrict IPv4 redirect acceptance"),
    ("net.ipv4.conf.all.send_redirects", "Prevent sending IPv4 ICMP redirects"),
    ("net.ipv4.conf.all.accept_source_route", "Ignore IPv4 source-routed packets"),
    ("net.ipv4.conf.all.log_martians", "Log packets with impossible source addresses"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "Ignore ICMP broadcast echo requests"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "Ignore bogus ICMP error responses"),
    ("net.ipv4.tcp_syncookies", "Enable TCP SYN-cookie protection"),
    ("net.ipv6.conf.all.accept_redirects", "Ignore IPv6 router-advertisement redirects"),
    ("net.ipv6.conf.default.accept_redirects", "Ignore IPv6 redirect (default)"),
    ("net.ipv6.conf.all.accept_source_route", "Ignore IPv6 source-routed packets"),
    # Memory protection
    ("vm.mmap_min_addr", "Minimum virtual address for mmap (NULL-dereference guard)"),
]


class SysctlCollector:
    """Collect security-relevant kernel sysctl parameters from /proc/sys."""

    _PROC_SYS = Path("/proc/sys")

    # Map dotted sysctl key to the relative /proc/sys path.
    _PROC_SYS_SUBSTITUTIONS: ClassVar[dict[str, str]] = {}

    @staticmethod
    def _key_to_path(key: str) -> Path:
        """Convert a dotted sysctl key to its /proc/sys path."""
        return Path("/proc/sys") / key.replace(".", "/")

    def read_one(self, key: str) -> str | None:
        """Read a single sysctl value; return None when unavailable."""
        path = self._key_to_path(key)
        try:
            return path.read_text(encoding="utf-8", errors="replace").strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def collect(self) -> list[EvidenceItem]:
        """Collect all security-relevant sysctl parameters.

        Returns a list of :class:`~kasa.models.evidence.EvidenceItem` objects,
        one per sysctl key.  Keys that are unavailable or permission-restricted
        are included with an appropriate status so that downstream analyzers can
        distinguish *missing* from *explicitly disabled*.
        """
        items: list[EvidenceItem] = []

        for key, description in _SECURITY_SYSCTLS:
            path = self._key_to_path(key)
            source = EvidenceSource(
                path=str(path),
                description=description,
            )

            try:
                raw = path.read_text(encoding="utf-8", errors="replace").strip()
                items.append(
                    EvidenceItem(
                        key=f"sysctl.{key}",
                        value=raw,
                        status=EvidenceStatus.AVAILABLE,
                        source=source,
                    )
                )

            except FileNotFoundError:
                items.append(
                    EvidenceItem(
                        key=f"sysctl.{key}",
                        value=None,
                        status=EvidenceStatus.UNAVAILABLE,
                        source=source,
                        error=f"sysctl key unavailable: {key}",
                    )
                )

            except PermissionError:
                items.append(
                    EvidenceItem(
                        key=f"sysctl.{key}",
                        value=None,
                        status=EvidenceStatus.ERROR,
                        source=source,
                        error=f"Permission denied reading sysctl: {key}",
                    )
                )

            except OSError as exc:
                items.append(
                    EvidenceItem(
                        key=f"sysctl.{key}",
                        value=None,
                        status=EvidenceStatus.ERROR,
                        source=source,
                        error=f"Unable to read sysctl {key}: {exc}",
                    )
                )

        return items
