"""Linux kernel information collector."""

from __future__ import annotations

import contextlib
import platform
from pathlib import Path

from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    KernelInfo,
    KernelSnapshot,
)


class KernelCollector:
    """Collect read-only information about the running Linux kernel."""

    _PROC_CMDLINE = Path("/proc/cmdline")
    _LOCKDOWN = Path("/sys/kernel/security/lockdown")
    _LSM = Path("/sys/kernel/security/lsm")
    _SELINUX_ENFORCE = Path("/sys/fs/selinux/enforce")
    _SELINUX_POLICY_VERSION = Path("/sys/fs/selinux/policyvers")
    _IMA = Path("/sys/kernel/security/ima")
    _IMA_INTEGRITY = Path("/sys/kernel/security/integrity/ima")
    _EVM = Path("/sys/kernel/security/evm")
    _EVM_INTEGRITY = Path("/sys/kernel/security/integrity/evm/evm")
    _IPE = Path("/sys/kernel/security/ipe")

    def collect(self) -> KernelSnapshot:
        """Collect kernel metadata and kernel security evidence."""
        errors: list[str] = []

        kernel_info = KernelInfo(
            release=platform.release(),
            version=platform.version(),
            machine=platform.machine(),
            node=platform.node(),
            system=platform.system(),
            processor=platform.processor(),
        )

        command_line, command_line_evidence, command_line_error = (
            self._collect_command_line()
        )

        if command_line_error is not None:
            errors.append(command_line_error)

        lockdown, lockdown_evidence, lockdown_error = self._collect_lockdown()

        if lockdown_error is not None:
            errors.append(lockdown_error)

        _, lsm_evidence, lsm_error = self._collect_lsm()

        if lsm_error is not None:
            errors.append(lsm_error)

        _, selinux_evidence, selinux_error = self._collect_selinux()

        if selinux_error is not None:
            errors.append(selinux_error)

        _, ima_evidence, ima_error = self._collect_ima(command_line)

        if ima_error is not None:
            errors.append(ima_error)

        _, evm_evidence, evm_error = self._collect_evm(command_line)

        if evm_error is not None:
            errors.append(evm_error)

        _, ipe_evidence, ipe_error = self._collect_ipe(command_line)

        if ipe_error is not None:
            errors.append(ipe_error)

        return KernelSnapshot(
            kernel=kernel_info,
            command_line=command_line,
            lockdown=lockdown,
            evidence=[
                command_line_evidence,
                lockdown_evidence,
                lsm_evidence,
                selinux_evidence,
                ima_evidence,
                evm_evidence,
                ipe_evidence,
            ],
            collection_errors=errors,
        )

    def _collect_command_line(
        self,
    ) -> tuple[str | None, EvidenceItem, str | None]:
        source = EvidenceSource(
            path=str(self._PROC_CMDLINE),
            description="Kernel command-line parameters.",
        )

        try:
            raw_value = self._PROC_CMDLINE.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()

        except FileNotFoundError:
            error = f"Kernel command line not available: {self._PROC_CMDLINE}"

            return (
                None,
                EvidenceItem(
                    key="kernel.command_line",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        except OSError as exc:
            error = f"Unable to read kernel command line {self._PROC_CMDLINE}: {exc}"

            return (
                None,
                EvidenceItem(
                    key="kernel.command_line",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        return (
            raw_value,
            EvidenceItem(
                key="kernel.command_line",
                value=raw_value,
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    def _collect_lockdown(
        self,
    ) -> tuple[str | None, EvidenceItem, str | None]:
        source = EvidenceSource(
            path=str(self._LOCKDOWN),
            description="Current kernel lockdown state.",
        )

        try:
            raw_value = self._LOCKDOWN.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()

        except FileNotFoundError:
            error = f"Kernel lockdown interface unavailable: {self._LOCKDOWN}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        except PermissionError:
            error = f"Permission denied reading kernel lockdown: {self._LOCKDOWN}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        except OSError as exc:
            error = f"Unable to read kernel lockdown {self._LOCKDOWN}: {exc}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        active_mode = self._parse_lockdown_state(raw_value)

        return (
            active_mode,
            EvidenceItem(
                key="kernel.lockdown",
                value={
                    "raw": raw_value,
                    "active_mode": active_mode,
                },
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    def _collect_lsm(
        self,
    ) -> tuple[list[str] | None, EvidenceItem, str | None]:
        source = EvidenceSource(
            path=str(self._LSM),
            description="Active Linux Security Modules.",
        )

        try:
            raw_value = self._LSM.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()

        except FileNotFoundError:
            error = f"Active LSM interface unavailable: {self._LSM}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lsm",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        except PermissionError:
            error = f"Permission denied reading active LSMs: {self._LSM}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lsm",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        except OSError as exc:
            error = f"Unable to read active LSMs {self._LSM}: {exc}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lsm",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        active_modules = self._parse_lsm_state(raw_value)

        return (
            active_modules,
            EvidenceItem(
                key="kernel.lsm",
                value={
                    "raw": raw_value,
                    "active": active_modules,
                },
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    @staticmethod
    def _parse_lsm_state(value: str) -> list[str]:
        """Extract the active LSM list from comma-separated string."""
        return [module.strip() for module in value.split(",") if module.strip()]

    @staticmethod
    def _parse_lockdown_state(value: str) -> str | None:
        """Extract the active lockdown mode from the kernel interface."""
        for mode in ("none", "integrity", "confidentiality"):
            if f"[{mode}]" in value:
                return mode

        return None

    def _collect_selinux(
        self,
    ) -> tuple[dict[str, object] | None, EvidenceItem, str | None]:
        """Collect runtime SELinux state from the kernel securityfs interface."""
        source = EvidenceSource(
            path=str(self._SELINUX_ENFORCE),
            description="SELinux enforcement mode and policy version.",
        )

        try:
            enforce_raw = self._SELINUX_ENFORCE.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()

        except FileNotFoundError:
            error = f"SELinux interface unavailable: {self._SELINUX_ENFORCE}"

            return (
                None,
                EvidenceItem(
                    key="kernel.selinux",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        except PermissionError:
            error = (
                f"Permission denied reading SELinux enforce: {self._SELINUX_ENFORCE}"
            )

            return (
                None,
                EvidenceItem(
                    key="kernel.selinux",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        except OSError as exc:
            error = f"Unable to read SELinux enforce {self._SELINUX_ENFORCE}: {exc}"

            return (
                None,
                EvidenceItem(
                    key="kernel.selinux",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        if enforce_raw == "1":
            mode: str | None = "enforcing"
        elif enforce_raw == "0":
            mode = "permissive"
        else:
            error = (
                f"Unexpected SELinux enforce value {enforce_raw!r}: "
                f"{self._SELINUX_ENFORCE}"
            )
            return (
                None,
                EvidenceItem(
                    key="kernel.selinux",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        policy_version: int | None = None

        try:
            policyvers_raw = self._SELINUX_POLICY_VERSION.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()
            policy_version = int(policyvers_raw)

        except FileNotFoundError:
            pass  # Policy version is supplemental; enforcement mode already known.

        except PermissionError:
            pass

        except (OSError, ValueError):
            pass

        value: dict[str, object] = {
            "enabled": True,
            "mode": mode,
            "policy_version": policy_version,
        }

        return (
            value,
            EvidenceItem(
                key="kernel.selinux",
                value=value,
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    def _collect_ima(
        self,
        command_line: str | None = None,
    ) -> tuple[dict[str, object] | None, EvidenceItem, str | None]:
        """Collect runtime IMA (Integrity Measurement Architecture) state."""
        source = EvidenceSource(
            path=str(self._IMA),
            description="IMA runtime measurement and policy interface.",
        )

        try:
            if self._IMA.exists():
                target_dir = self._IMA
            elif self._IMA_INTEGRITY.exists():
                target_dir = self._IMA_INTEGRITY
            else:
                target_dir = None
        except PermissionError:
            error = f"Permission denied accessing IMA interface: {self._IMA}"
            return (
                None,
                EvidenceItem(
                    key="kernel.ima",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )
        except OSError as exc:
            error = f"Unable to access IMA interface {self._IMA}: {exc}"
            return (
                None,
                EvidenceItem(
                    key="kernel.ima",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        if target_dir is None:
            error = f"IMA interface unavailable: {self._IMA}"
            return (
                None,
                EvidenceItem(
                    key="kernel.ima",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        policy_available = False
        with contextlib.suppress(PermissionError, OSError):
            policy_available = (target_dir / "policy").exists()

        measurements_count: int | None = None
        try:
            raw_count = (
                (target_dir / "runtime_measurements_count")
                .read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                .strip()
            )
            measurements_count = int(raw_count)
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            pass

        violations_count: int | None = None
        try:
            raw_violations = (
                (target_dir / "violations")
                .read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                .strip()
            )
            violations_count = int(raw_violations)
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            pass

        boot_params = self._parse_cmdline_params(command_line, "ima")

        appraisal_state = boot_params.get("ima_appraise", "unknown")
        if appraisal_state == "1":
            appraisal_state = "enforce"

        value: dict[str, object] = {
            "supported": True,
            "interface_path": str(target_dir),
            "policy_available": policy_available,
            "runtime_measurements_count": measurements_count,
            "violations_count": violations_count,
            "boot_parameters": boot_params,
            "appraisal_runtime_state": appraisal_state,
        }

        return (
            value,
            EvidenceItem(
                key="kernel.ima",
                value=value,
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    def _collect_evm(
        self,
        command_line: str | None = None,
    ) -> tuple[dict[str, object] | None, EvidenceItem, str | None]:
        """Collect runtime EVM (Extended Verification Module) state."""
        source = EvidenceSource(
            path=str(self._EVM),
            description="EVM runtime state and metadata verification interface.",
        )

        try:
            if self._EVM.exists():
                target_path = self._EVM
            elif self._EVM_INTEGRITY.exists():
                target_path = self._EVM_INTEGRITY
            else:
                target_path = None
        except PermissionError:
            error = f"Permission denied accessing EVM interface: {self._EVM}"
            return (
                None,
                EvidenceItem(
                    key="kernel.evm",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )
        except OSError as exc:
            error = f"Unable to access EVM interface {self._EVM}: {exc}"
            return (
                None,
                EvidenceItem(
                    key="kernel.evm",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        if target_path is None:
            error = f"EVM interface unavailable: {self._EVM}"
            return (
                None,
                EvidenceItem(
                    key="kernel.evm",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        status_raw: str | None = None
        status_flags: int | None = None
        readable = False

        try:
            status_raw = target_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()
            status_flags = int(status_raw)
            readable = True
        except (PermissionError, FileNotFoundError, OSError, ValueError):
            readable = False

        boot_params = self._parse_cmdline_params(command_line, "evm")

        active_state = "unknown"
        if status_flags is not None:
            if status_flags == 0:
                active_state = "uninitialized"
            elif (status_flags & 1) and (status_flags & 2):
                active_state = "complete"
            elif status_flags & 1:
                active_state = "hmac_initialized"
            elif status_flags & 2:
                active_state = "x509_initialized"
            else:
                active_state = f"flags_{status_flags}"

        value: dict[str, object] = {
            "supported": True,
            "interface_path": str(target_path),
            "readable": readable,
            "status_raw": status_raw,
            "status_flags": status_flags,
            "boot_parameters": boot_params,
            "active_state": active_state,
        }

        return (
            value,
            EvidenceItem(
                key="kernel.evm",
                value=value,
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    def _collect_ipe(
        self,
        command_line: str | None = None,
    ) -> tuple[dict[str, object] | None, EvidenceItem, str | None]:
        """Collect runtime IPE (Integrity Policy Enforcement) state."""
        source = EvidenceSource(
            path=str(self._IPE),
            description="IPE policy deployment and enforcement interface.",
        )

        try:
            exists = self._IPE.exists()
        except PermissionError:
            error = f"Permission denied accessing IPE interface: {self._IPE}"
            return (
                None,
                EvidenceItem(
                    key="kernel.ipe",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )
        except OSError as exc:
            error = f"Unable to access IPE interface {self._IPE}: {exc}"
            return (
                None,
                EvidenceItem(
                    key="kernel.ipe",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        if not exists:
            error = f"IPE interface unavailable: {self._IPE}"
            return (
                None,
                EvidenceItem(
                    key="kernel.ipe",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        enforce: bool | None = None
        try:
            raw_enforce = (
                (self._IPE / "enforce")
                .read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                .strip()
            )
            if raw_enforce == "1":
                enforce = True
            elif raw_enforce == "0":
                enforce = False
        except (FileNotFoundError, PermissionError, OSError):
            pass

        success_audit: bool | None = None
        try:
            raw_audit = (
                (self._IPE / "success_audit")
                .read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                .strip()
            )
            if raw_audit == "1":
                success_audit = True
            elif raw_audit == "0":
                success_audit = False
        except (FileNotFoundError, PermissionError, OSError):
            pass

        policies: list[str] = []
        active_policies: list[str] = []
        policies_dir = self._IPE / "policies"
        try:
            if policies_dir.is_dir():
                for policy_entry in sorted(policies_dir.iterdir()):
                    policies.append(policy_entry.name)
                    active_file = policy_entry / "active"
                    try:
                        if (
                            active_file.exists()
                            and active_file.read_text(
                                encoding="utf-8",
                                errors="replace",
                            ).strip()
                            == "1"
                        ):
                            active_policies.append(policy_entry.name)
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass

        boot_params = self._parse_cmdline_params(command_line, "ipe")

        value: dict[str, object] = {
            "supported": True,
            "interface_path": str(self._IPE),
            "enforce": enforce,
            "success_audit": success_audit,
            "policies": policies,
            "active_policies": active_policies,
            "boot_parameters": boot_params,
        }

        return (
            value,
            EvidenceItem(
                key="kernel.ipe",
                value=value,
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    @staticmethod
    def _parse_cmdline_params(
        command_line: str | None,
        prefix: str,
    ) -> dict[str, str]:
        """Extract kernel boot parameters starting with a given prefix."""
        if not command_line:
            return {}

        params: dict[str, str] = {}
        for token in command_line.split():
            if not token.startswith(prefix):
                continue
            if "=" in token:
                key, val = token.split("=", 1)
                params[key] = val
            else:
                params[token] = "1"

        return params
