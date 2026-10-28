"""Linux kernel configuration collector."""

from __future__ import annotations

import gzip
import re
from pathlib import Path

from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
)


class KernelConfigCollector:
    """Collect the configuration of the currently running Linux kernel."""

    _PROC_CONFIG = Path("/proc/config.gz")
    _CONFIG_TEMPLATE = "/boot/config-{release}"
    _MODULE_CONFIG_TEMPLATE = "/lib/modules/{release}/build/.config"

    _CONFIG_LINE = re.compile(r"^(?P<key>[A-Za-z0-9_]+)=(?P<value>.+)$")
    _NOT_SET_LINE = re.compile(r"^# (?P<key>[A-Za-z0-9_]+) is not set$")

    def collect(self, kernel_release: str) -> list[EvidenceItem]:
        """Collect kernel configuration using ordered fallback sources."""
        sources = self._candidate_sources(kernel_release)

        for source in sources:
            evidence = self._read_source(source)

            if evidence.status is EvidenceStatus.AVAILABLE:
                return [evidence]

        return [
            EvidenceItem(
                key="kernel.config",
                value=None,
                status=EvidenceStatus.UNAVAILABLE,
                source=EvidenceSource(
                    path="multiple",
                    description=("No readable kernel configuration source was found."),
                ),
                error=(
                    "Kernel configuration is unavailable from all supported sources."
                ),
            )
        ]

    def _candidate_sources(self, kernel_release: str) -> list[Path]:
        """Return configuration sources in preferred order."""
        return [
            self._PROC_CONFIG,
            Path(self._CONFIG_TEMPLATE.format(release=kernel_release)),
            Path(
                self._MODULE_CONFIG_TEMPLATE.format(
                    release=kernel_release,
                )
            ),
        ]

    def _read_source(self, path: Path) -> EvidenceItem:
        """Read and parse a single kernel configuration source."""
        source = EvidenceSource(
            path=str(path),
            description="Linux kernel build configuration.",
        )

        try:
            raw = self._read_config(path)
            config = self._parse_config(raw)

        except FileNotFoundError:
            return EvidenceItem(
                key="kernel.config",
                value=None,
                status=EvidenceStatus.UNAVAILABLE,
                source=source,
                error=f"Configuration source does not exist: {path}",
            )

        except PermissionError:
            return EvidenceItem(
                key="kernel.config",
                value=None,
                status=EvidenceStatus.ERROR,
                source=source,
                error=f"Permission denied reading configuration: {path}",
            )

        except OSError as exc:
            return EvidenceItem(
                key="kernel.config",
                value=None,
                status=EvidenceStatus.ERROR,
                source=source,
                error=f"Unable to read configuration {path}: {exc}",
            )

        except UnicodeDecodeError as exc:
            return EvidenceItem(
                key="kernel.config",
                value=None,
                status=EvidenceStatus.ERROR,
                source=source,
                error=f"Invalid configuration encoding {path}: {exc}",
            )

        return EvidenceItem(
            key="kernel.config",
            value={
                "source": str(path),
                "options": config,
                "option_count": len(config),
            },
            status=EvidenceStatus.AVAILABLE,
            source=source,
        )

    @staticmethod
    def _read_config(path: Path) -> str:
        """Read plain-text or gzip-compressed kernel configuration."""
        if path.name == "config.gz":
            with gzip.open(path, mode="rt", encoding="utf-8") as file:
                return file.read()

        return path.read_text(encoding="utf-8")

    def _parse_config(self, content: str) -> dict[str, str]:
        """Parse Linux .config syntax into normalized key/value pairs."""
        config: dict[str, str] = {}

        for raw_line in content.splitlines():
            line = raw_line.strip()

            if not line or line.startswith("##"):
                continue

            not_set_match = self._NOT_SET_LINE.match(line)

            if not_set_match:
                config[not_set_match.group("key")] = "n"
                continue

            config_match = self._CONFIG_LINE.match(line)

            if config_match:
                config[config_match.group("key")] = config_match.group("value")

        return config
