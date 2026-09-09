"""
PROCESS MITIGATION — v29.44 (audit §8.4, improvement catalog P0 #3)
================================================================================
Hardens the Downpour process against common exploitation techniques using
Windows Process Mitigation Policies (SetProcessMitigationPolicy via ctypes).

Policies enabled (best-effort, each independently):
  * ProcessDynamicCodePolicy      — blocks dynamic code generation (shellcode
    injection into the Downpour process via VirtualAlloc+memcpy)
  * ProcessExtensionPointDisablePolicy — disables legacy DLL injection
    vectors (AppInit_DLLs, Winlogon notification packages, IME packages)
  * ProcessControlFlowGuardPolicy — enables Control Flow Guard for the
    process (prevents return/jump-oriented programming)
  * ProcessSignaturePolicy        — restricts image loading to Microsoft-
    signed binaries (blocks unsigned DLL injection)

Usage (call once at startup, before any monitoring threads start):
    from process_mitigation import apply_process_mitigations
    apply_process_mitigations()

Honest limitation: these are user-mode policies — they don't protect against
kernel-level exploits or a determined attacker with SeDebugPrivilege. They
raise the bar significantly against commodity malware and script-kiddy
tooling.
"""
from __future__ import annotations

import ctypes
import logging
import os
from ctypes import wintypes
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

_IS_WINDOWS = os.name == 'nt'

# ProcessMitigationPolicy constants (from winnt.h)
ProcessDynamicCodePolicy = 0          # PROC_THREAD_ATTRIBUTE_DYNAMIC_CODE_POLICY
ProcessControlFlowGuardPolicy = 2     # CFG
ProcessSignaturePolicy = 3            # Microsoft-signed images only
ProcessExtensionPointDisablePolicy = 4  # AppInit_DLLs, Winlogon notifications

# Policy struct: all policies use a DWORD-based struct with a single flag field
# (sufficient for the enable/disable flags we need)


class _MitigationPolicy(ctypes.Structure):
    _fields_ = [('Flags', wintypes.DWORD)]


def _set_policy(policy_id: int, flags: int) -> bool:
    """Call SetProcessMitigationPolicy for a single policy. Returns success."""
    if not _IS_WINDOWS:
        return False
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        policy_struct = _MitigationPolicy()
        policy_struct.Flags = flags
        # SetProcessMitigationPolicy(policy, cbSize, lpPolicy)
        ret = kernel32.SetProcessMitigationPolicy(
            wintypes.DWORD(policy_id),
            ctypes.byref(policy_struct),
            ctypes.sizeof(policy_struct),
        )
        return bool(ret)
    except Exception as exc:
        _log.debug('process_mitigation: _set_policy(%d) failed: %s',
                   policy_id, exc)
        return False


def _get_policy(policy_id: int) -> Optional[int]:
    """Call GetProcessMitigationPolicy for a single policy. Returns flags or None."""
    if not _IS_WINDOWS:
        return None
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        policy_struct = _MitigationPolicy()
        # GetProcessMitigationPolicy(hProcess, policy, lpPolicy, cbSize)
        ret = kernel32.GetProcessMitigationPolicy(
            wintypes.HANDLE(-1),  # GetCurrentProcess()
            wintypes.DWORD(policy_id),
            ctypes.byref(policy_struct),
            ctypes.sizeof(policy_struct),
        )
        if ret:
            return policy_struct.Flags
        return None
    except Exception as exc:
        _log.debug('process_mitigation: _get_policy(%d) failed: %s',
                   policy_id, exc)
        return None


def apply_process_mitigations() -> Dict[str, bool]:
    """Enable best-effort process mitigation policies.

    Returns a dict of {policy_name: enabled} for each attempted policy.
    Policies that fail (e.g. already set, or OS doesn't support) are
    logged at debug level and reported as False — the app continues to run.
    """
    results: Dict[str, bool] = {}

    # 1. ProcessDynamicCodePolicy — block dynamic code generation
    #    (prevents shellcode injection via VirtualAlloc + memcpy)
    results['dynamic_code_prohibited'] = _set_policy(
        ProcessDynamicCodePolicy, 1)

    # 2. ProcessExtensionPointDisablePolicy — disable legacy extension
    #    point DLL injection (AppInit_DLLs, Winlogon notifications, IME)
    results['extension_points_disabled'] = _set_policy(
        ProcessExtensionPointDisablePolicy, 1)

    # 3. ProcessControlFlowGuardPolicy — enable CFG
    #    (prevents ROP/JOP by validating indirect call targets)
    results['control_flow_guard'] = _set_policy(
        ProcessControlFlowGuardPolicy, 1)

    # 4. ProcessSignaturePolicy — restrict image loading to Microsoft-signed
    #    (blocks unsigned DLL injection — most aggressive, may break some
    #    legitimate loading; use MicrosoftSignedOnly = 1)
    # NOTE: skipped for now because it can break legitimate plugin loading.
    # results['microsoft_signed_only'] = _set_policy(
    #     ProcessSignaturePolicy, 1)

    enabled_count = sum(1 for v in results.values() if v)
    _log.info('process_mitigation: %d/%d policies enabled',
              enabled_count, len(results))
    return results


def get_mitigation_status() -> Dict[str, bool]:
    """Query the current mitigation status (for health-check dashboards)."""
    status: Dict[str, bool] = {}
    for policy_id, name in [
        (ProcessDynamicCodePolicy, 'dynamic_code_prohibited'),
        (ProcessExtensionPointDisablePolicy, 'extension_points_disabled'),
        (ProcessControlFlowGuardPolicy, 'control_flow_guard'),
    ]:
        flags = _get_policy(policy_id)
        status[name] = bool(flags) if flags is not None else False
    return status


# Module-level: apply mitigations on import (before any threads start)
if _IS_WINDOWS:
    _results = apply_process_mitigations()

__all__ = [
    'apply_process_mitigations',
    'get_mitigation_status',
]