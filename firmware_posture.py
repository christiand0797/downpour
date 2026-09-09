"""
FIRMWARE & PLATFORM TRUST POSTURE — v29.46
================================================================================
Checks the boot/firmware trust chain and platform defense baseline that no
existing Downpour module covered:

  1. BitLocker    — OS-volume encryption/protection (ransomware recovery)
  2. Secure Boot  — UEFI secure boot (pre-OS bootkit defense, T1542)
  3. TPM          — present / ready / enabled (keys sealed at boot)
  4. LSA PPL      — RunAsPPL (blocks LSASS read by non-PPL, T1003)
  5. Credential Guard — LsaCfgFlags + virtualization-based isolation
  6. VBS / HVCI   — DeviceGuard memory-integrity posture
  7. SMBv1        — legacy worm-able protocol must stay off (T1210)
  8. Patch health — wuauserv disabled = no security updates ever arrive

Alert model mirrors persistence_watchers.PersistenceAlert so findings bridge
into the same alert pipeline ([FIRMWARE] tag). Posture is STATIC state, so
this is a one-shot scan (monitor start / manual re-check) — NOT a polling
loop, which would just re-spam the same findings every cycle.

PowerShell probes run with -NoProfile -NonInteractive, CREATE_NO_WINDOW and
a hard timeout; registry probes use winreg. Unreadable states (non-admin,
non-UEFI systems, missing WMI) degrade to UNKNOWN — never to a false alert.
Stdlib-only; never raises into the caller.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_PS_TIMEOUT = 20


@dataclass
class FirmwareAlert:
    """One firmware/posture finding (mirrors PersistenceAlert shape)."""
    source: str          # 'bitlocker'|'secureboot'|'tpm'|'lsa'|'credguard'|
                         # 'vbs'|'smbv1'|'patch'
    technique: str       # MITRE where applicable, else friendly tag
    severity: str        # LOW/MEDIUM/HIGH/CRITICAL
    description: str
    detail: str


def _ps(command: str) -> Optional[str]:
    """Run a short PowerShell probe; None on any failure/timeout."""
    try:
        flags = 0
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            flags = subprocess.CREATE_NO_WINDOW
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', command],
            capture_output=True, text=True, timeout=_PS_TIMEOUT,
            creationflags=flags)
        if proc.returncode != 0:
            return None
        return (proc.stdout or '').strip() or None
    except Exception as exc:                # defensive — never raise
        _log.debug('firmware_posture _ps: %s', exc)
        return None


def _reg_get(root: int, subkey: str, value: str) -> Optional[Any]:
    """Read one registry DWORD/string; None when absent/unreadable."""
    try:
        import winreg
        with winreg.OpenKey(root, subkey, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            data, _type = winreg.QueryValueEx(key, value)
            return data
    except Exception:
        return None


HKLM = 0x80000002  # winreg.HKEY_LOCAL_MACHINE (import kept local-safe)


# ══════════════════════════════════════════════════════════════════════════════
# Individual checks — each returns (List[FirmwareAlert], status_str)
# ══════════════════════════════════════════════════════════════════════════════
def check_bitlocker() -> Tuple[List[FirmwareAlert], str]:
    """OS-volume BitLocker protection (Get-BitLockerVolume / manage-bde)."""
    out = _ps('Get-BitLockerVolume -ErrorAction SilentlyContinue | '
              'Select-Object MountPoint,VolumeStatus,ProtectionStatus | '
              'ConvertTo-Json -Compress')
    if out:
        try:
            data = json.loads(out)
            vols = data if isinstance(data, list) else [data]
            alerts: List[FirmwareAlert] = []
            for v in vols:
                if not isinstance(v, dict):
                    continue
                mount = str(v.get('MountPoint', '')).strip()
                prot = str(v.get('ProtectionStatus', '')).strip().lower()
                status = str(v.get('VolumeStatus', '')).strip()
                if mount.rstrip(':').lower() != os.environ.get(
                        'SystemDrive', 'C:').rstrip(':').lower():
                    continue
                if prot == 'off':
                    alerts.append(FirmwareAlert(
                        source='bitlocker', technique='T1490',
                        severity='HIGH',
                        description='OS volume not BitLocker-protected',
                        detail=f'{mount}: ProtectionStatus=off '
                               f'(VolumeStatus={status}) — ransomware and '
                               f'thieves can read everything'))
            if alerts:
                return alerts, 'unprotected'
            return alerts, 'protected'
        except Exception as exc:
            _log.debug('bitlocker parse: %s', exc)
    # Fallback: manage-bde
    drive = os.environ.get('SystemDrive', 'C:')
    out2 = _ps(f'manage-bde -status {drive}')
    if out2:
        low = out2.lower()
        if 'protection status: protection off' in low:
            return ([FirmwareAlert(
                source='bitlocker', technique='T1490', severity='HIGH',
                description='OS volume not BitLocker-protected',
                detail=f'{drive}: manage-bde reports protection off')],
                'unprotected')
        if 'protection status: protection on' in low:
            return [], 'protected'
    return [], 'unknown'


def check_secure_boot() -> Tuple[List[FirmwareAlert], str]:
    """UEFI Secure Boot state (Confirm-SecureBootUEFI + registry fallback)."""
    out = _ps('Confirm-SecureBootUEFI')
    if out is not None:
        val = out.strip().lower()
        if val == 'false':
            return ([FirmwareAlert(
                source='secureboot', technique='T1542', severity='MEDIUM',
                description='UEFI Secure Boot is disabled',
                detail='Confirm-SecureBootUEFI returned False — bootkits/'
                       'firmware implants face no signature check')],
                'disabled')
        if val == 'true':
            return [], 'enabled'
    reg = _reg_get(HKLM,
                   r'SYSTEM\CurrentControlSet\Control\SecureBoot\State',
                   'UEFISecureBootEnabled')
    if reg is not None:
        if int(reg) == 0:
            return ([FirmwareAlert(
                source='secureboot', technique='T1542', severity='MEDIUM',
                description='UEFI Secure Boot is disabled',
                detail='UEFISecureBootEnabled=0')], 'disabled')
        return [], 'enabled'
    return [], 'unknown'                    # legacy BIOS or non-admin


def check_tpm() -> Tuple[List[FirmwareAlert], str]:
    """TPM present/ready/enabled (Get-Tpm, admin)."""
    out = _ps('Get-Tpm -ErrorAction SilentlyContinue | '
              'Select-Object TpmPresent,TpmReady,TpmEnabled | '
              'ConvertTo-Json -Compress')
    if not out:
        return [], 'unknown'
    try:
        data = json.loads(out)
        if isinstance(data, list):
            data = data[0] if data else {}
        present = bool(data.get('TpmPresent'))
        ready = bool(data.get('TpmReady'))
        enabled = bool(data.get('TpmEnabled'))
        if not present:
            return ([FirmwareAlert(
                source='tpm', technique='TPM', severity='LOW',
                description='No TPM present',
                detail='Get-Tpm: TpmPresent=False — BitLocker cannot seal '
                       'keys in hardware')], 'absent')
        if not (ready and enabled):
            return ([FirmwareAlert(
                source='tpm', technique='TPM', severity='LOW',
                description='TPM not ready/enabled',
                detail=f'Get-Tpm: TpmReady={ready} TpmEnabled={enabled}')],
                'not_ready')
        return [], 'ready'
    except Exception as exc:
        _log.debug('tpm parse: %s', exc)
        return [], 'unknown'


def check_lsa_ppl() -> Tuple[List[FirmwareAlert], str]:
    """LSA Protection (RunAsPPL) — blocks open-process on LSASS (T1003)."""
    val = _reg_get(HKLM, r'SYSTEM\CurrentControlSet\Control\Lsa',
                   'RunAsPPL')
    if val is None:
        return ([FirmwareAlert(
            source='lsa', technique='T1003', severity='HIGH',
            description='LSA Protection (RunAsPPL) is not enabled',
            detail='HKLM\\SYSTEM\\...\\Lsa\\RunAsPPL missing — any admin '
                   'process can dump LSASS credentials')], 'disabled')
    if int(val) == 0:
        return ([FirmwareAlert(
            source='lsa', technique='T1003', severity='HIGH',
            description='LSA Protection (RunAsPPL) is disabled',
            detail='RunAsPPL=0 — credential dumping is trivially easy')],
            'disabled')
    return [], 'enabled'


def check_credential_guard() -> Tuple[List[FirmwareAlert], str]:
    """Credential Guard (LsaCfgFlags) — virtualization-isolated secrets."""
    val = _reg_get(HKLM, r'SYSTEM\CurrentControlSet\Control\Lsa',
                   'LsaCfgFlags')
    if val is None:
        return ([FirmwareAlert(
            source='credguard', technique='T1003', severity='MEDIUM',
            description='Credential Guard is not enabled',
            detail='LsaCfgFlags missing — LSASS secrets are not '
                   'virtualization-isolated')], 'disabled')
    if int(val) == 0:
        return ([FirmwareAlert(
            source='credguard', technique='T1003', severity='MEDIUM',
            description='Credential Guard is disabled',
            detail='LsaCfgFlags=0')], 'disabled')
    return [], 'enabled'


def check_vbs_hvci() -> Tuple[List[FirmwareAlert], str]:
    """VBS + HVCI (memory integrity) posture."""
    alerts: List[FirmwareAlert] = []
    vbs = _reg_get(HKLM, r'SYSTEM\CurrentControlSet\Control\DeviceGuard',
                   'EnableVirtualizationBasedSecurity')
    hvci = _reg_get(
        HKLM, r'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios'
              r'\HypervisorEnforcedCodeIntegrity', 'Enabled')
    if hvci is not None and int(hvci) == 1:
        return [], 'hvci_enabled'
    if vbs is None and hvci is None:
        alerts.append(FirmwareAlert(
            source='vbs', technique='VBS/HVCI', severity='LOW',
            description='Virtualization-Based Security not configured',
            detail='DeviceGuard registry keys absent — kernel exploit '
                   'mitigations (HVCI) unavailable'))
        return alerts, 'disabled'
    if hvci is not None and int(hvci) == 0:
        alerts.append(FirmwareAlert(
            source='vbs', technique='VBS/HVCI', severity='LOW',
            description='HVCI (memory integrity) is disabled',
            detail='HypervisorEnforcedCodeIntegrity\\Enabled=0 — kernel '
                   'driver exploits are less contained'))
        return alerts, 'hvci_disabled'
    return alerts, 'unknown'


def check_smb1() -> Tuple[List[FirmwareAlert], str]:
    """SMBv1 must stay off (WannaCry/NotPetya worm path, T1210)."""
    val = _reg_get(HKLM, r'SYSTEM\CurrentControlSet\Services\LanmanServer'
                         r'\Parameters', 'SMB1')
    if val is None:
        # Windows 10 1709+ default: capability absent = disabled
        return [], 'absent_default_off'
    if int(val) != 0:
        return ([FirmwareAlert(
            source='smbv1', technique='T1210', severity='HIGH',
            description='SMBv1 protocol is enabled',
            detail='LanmanServer\\Parameters\\SMB1=1 — WannaCry/NotPetya-'
                   'class worm propagation path is open')], 'enabled')
    return [], 'disabled'


def check_patch_service() -> Tuple[List[FirmwareAlert], str]:
    """Windows Update service must not be disabled (patch health)."""
    val = _reg_get(HKLM, r'SYSTEM\CurrentControlSet\Services\wuauserv',
                   'Start')
    if val is None:
        return [], 'unknown'
    if int(val) == 4:                       # SERVICE_DISABLED
        return ([FirmwareAlert(
            source='patch', technique='PatchHealth', severity='HIGH',
            description='Windows Update service is disabled',
            detail='wuauserv Start=4 — this device will never receive '
                   'security patches')], 'disabled')
    return [], 'ok'


# ══════════════════════════════════════════════════════════════════════════════
# Combined entry point
# ══════════════════════════════════════════════════════════════════════════════
_CHECKS = (check_bitlocker, check_secure_boot, check_tpm, check_lsa_ppl,
           check_credential_guard, check_vbs_hvci, check_smb1,
           check_patch_service)


def collect_posture() -> Tuple[List[FirmwareAlert], Dict[str, str]]:
    """Run every posture check. Returns (alerts, per-source status map)."""
    alerts: List[FirmwareAlert] = []
    status: Dict[str, str] = {}
    for check in _CHECKS:
        try:
            found, state = check()
            alerts.extend(found)
            status[check.__name__.replace('check_', '')] = state
        except Exception as exc:            # defensive — never raise
            _log.debug('firmware_posture %s: %s', check.__name__, exc)
    return alerts, status


def run_all_firmware_checks() -> List[FirmwareAlert]:
    """Alerts only — wiring-compatible with the persistence-watch bridge."""
    return collect_posture()[0]


def get_posture_summary() -> Dict[str, str]:
    """Status map only — for GUI/report display."""
    return collect_posture()[1]


__all__ = ['FirmwareAlert', 'check_bitlocker', 'check_secure_boot',
           'check_tpm', 'check_lsa_ppl', 'check_credential_guard',
           'check_vbs_hvci', 'check_smb1', 'check_patch_service',
           'collect_posture', 'run_all_firmware_checks',
           'get_posture_summary']
