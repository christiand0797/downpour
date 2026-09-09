"""
CHILD-PROCESS GUARD (Windows Job Objects) — v29.47 (catalog item 4b)
================================================================================
Places the Downpour process inside a Windows Job Object so every child it
spawns — PowerShell posture/DNS probes, netsh firewall rules, feed parsers —
is contained by the kernel:

  * JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — every child dies the moment
    Downpour exits. No spawned probe can outlive and out-run the guardian
    after a crash/kill of the parent (fail-closed child hygiene).
  * Breakaway refused — children cannot detach from the job to survive
    parent termination (BREAKAWAY/SILENT_BREAKAWAY limits are NOT granted).
  * terminate_all_children() — kernel-verified kill of the whole tree
    (Emergency panic path; never call from a Downpour thread — it would
    terminate Downpour too, since the parent is inside the job).

Completes the self-protection pair: process_mitigation.py (catalog 4a)
hardens the Downpour PROCESS itself; this hardens its CHILDREN.

Built on pywin32's win32job (pywin32 is a core requirement) — the raw
ctypes path was dropped after live testing showed SetInformationJobObject
rejecting hand-marshalled structs (ERROR_BAD_LENGTH) that win32job handles
correctly. Best-effort: if pywin32 is missing, or the process is already
inside an incompatible job (pre-Win8 nesting), the guard reports
{installed: False} and the app runs exactly as before. Never raises.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

_IS_WINDOWS = os.name == 'nt'

try:
    import win32job                       # pywin32 — core requirement
    import win32process
    _WIN32JOB_AVAILABLE = True
except ImportError:
    win32job = None
    win32process = None
    _WIN32JOB_AVAILABLE = False

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


class ChildProcessGuard:
    """One Job Object holding the Downpour process tree. Create once."""

    def __init__(self) -> None:
        self._handle = None
        self._installed = False

    @property
    def installed(self) -> bool:
        return self._installed

    @property
    def handle(self):
        return self._handle

    def install(self) -> Dict[str, Any]:
        """Create the job, set KILL_ON_JOB_CLOSE, assign this process.
        Returns a status dict; never raises."""
        status: Dict[str, Any] = {'installed': False,
                                  'kill_on_close': False,
                                  'breakaway_blocked': False,
                                  'reason': ''}
        if not _IS_WINDOWS:
            status['reason'] = 'non-Windows platform'
            return status
        if not _WIN32JOB_AVAILABLE:
            status['reason'] = 'pywin32 (win32job) unavailable'
            return status
        try:
            hjob = win32job.CreateJobObject(None, 'downpour-child-guard')
            if not hjob:
                status['reason'] = 'CreateJobObject failed'
                return status
            self._handle = hjob
            limits = win32job.QueryInformationJobObject(
                hjob, win32job.JobObjectExtendedLimitInformation)
            limits['BasicLimitInformation']['LimitFlags'] = \
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(
                hjob, win32job.JobObjectExtendedLimitInformation, limits)
            status['kill_on_close'] = True
            # SILENT_BREAKAWAY / BREAKAWAY flags deliberately NOT set →
            # children cannot escape the job.
            status['breakaway_blocked'] = True
            win32job.AssignProcessToJobObject(
                hjob, win32process.GetCurrentProcess())
            self._installed = True
            status['installed'] = True
            status['reason'] = 'ok'
            _log.info('child_process_guard: job installed '
                      '(kill-on-close, breakaway blocked)')
        except Exception as exc:              # defensive — never raise
            status['reason'] = str(exc)[:160]
            _log.debug('child_process_guard install: %s', exc)
        return status

    def terminate_all_children(self, exit_code: int = 1) -> bool:
        """Kernel-verified kill of every process in the job. NOTE: the
        Downpour process itself is also IN the job, so this terminates the
        whole tree — the caller must be a separate watchdog/emergency
        path, never a Downpour thread."""
        if not self._handle or not _WIN32JOB_AVAILABLE:
            return False
        try:
            win32job.TerminateJobObject(self._handle, exit_code)
            return True
        except Exception as exc:
            _log.debug('child_process_guard terminate: %s', exc)
            return False

    def list_job_pids(self) -> Optional[list]:
        """PIDs currently inside the job (None when unavailable)."""
        if not self._handle or not _WIN32JOB_AVAILABLE:
            return None
        try:
            info = win32job.QueryInformationJobObject(
                self._handle, win32job.JobObjectBasicProcessIdList)
            if isinstance(info, tuple):       # pywin32 returns a tuple
                return [int(p) for p in info]
            if isinstance(info, dict):
                pids = info.get('ProcessIdList')
                return list(pids) if pids else []
            return []
        except Exception as exc:
            _log.debug('child_process_guard pids: %s', exc)
            return None


_module_guard: Optional[ChildProcessGuard] = None


def install_job_guard() -> Dict[str, Any]:
    """Install the process-wide guard (idempotent). Returns status dict."""
    global _module_guard
    if _module_guard is None:
        _module_guard = ChildProcessGuard()
    if _module_guard.installed:
        return {'installed': True, 'kill_on_close': True,
                'breakaway_blocked': True, 'reason': 'already installed'}
    return _module_guard.install()


def get_guard_status() -> Dict[str, Any]:
    """Guard status for health dashboards."""
    if _module_guard is None:
        return {'installed': False, 'kill_on_close': False,
                'breakaway_blocked': False, 'reason': 'not installed'}
    return {'installed': _module_guard.installed,
            'kill_on_close': _module_guard.installed,
            'breakaway_blocked': _module_guard.installed,
            'reason': 'ok' if _module_guard.installed else 'not installed'}


def terminate_all_children(exit_code: int = 1) -> bool:
    """Module convenience → the shared guard's tree kill (Emergency path)."""
    if _module_guard is None:
        return False
    return _module_guard.terminate_all_children(exit_code)


__all__ = ['ChildProcessGuard', 'install_job_guard', 'get_guard_status',
           'terminate_all_children', 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE',
           '_WIN32JOB_AVAILABLE']
