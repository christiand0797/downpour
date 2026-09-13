"""
NATIVE PROBES — v29.60 "de-PowerShell" layer
================================================================================
Every Windows capability in this module replaces a former PowerShell
subprocess call with the SAME underlying native API that PowerShell itself
wraps. Features are preserved 1:1 — only the transport changes:

  * Get-WmiObject / Get-CimInstance   -> WMI via COM (WbemScripting.SWbemLocator)
  * Get-DnsClientCache                -> DnsGetCacheDataTable  (dnsapi.dll)
  * Get-WinEvent                      -> EvtQuery/EvtNext      (wevtapi.dll)
  * Get-AuthenticodeSignature         -> WinVerifyTrust        (wintrust.dll)
  * Get-SpeculationControlSettings    -> NtQuerySystemInformation(201)
  * Get-Clipboard                     -> OpenClipboard/GetClipboardData
  * Get-Item -Stream (ADS)            -> FindFirstStream (kernel32)
  * Out-Minidump                      -> MiniDumpWriteDump     (dbghelp.dll)
  * Add/Remove-VpnConnection          -> rasphone.pbk store + RAS verify
  * Get-MpPreference / Set-MpPreference -> WMI root\\Microsoft\\Windows\\Defender
                                        + Policies-registry fallback
  * Confirm-SecureBootUEFI            -> registry SecureBoot\\State
  * Get-ExecutionPolicy               -> registry ShellIds
  * New-Object -ComObject ...Update   -> win32com Dispatch (COM is native)
  * WScript.Shell CreateShortcut      -> win32com Dispatch (COM is native)

Design rules:
  * Every function is best-effort and NEVER raises — failures return the
    documented empty/default result, matching the old try/except blocks.
  * COM helpers work on BOTH STA and MTA threads (pool threads run
    CoInitializeEx(0)=MTA; SWbemLocator Dispatch works under MTA, unlike
    the wmi module's GetObject-moniker path).
  * Stdlib + pywin32 only (pywin32 is a core requirement).
"""
from __future__ import annotations

import ctypes
import logging
import os
import winreg  # noqa: F401  (used by module-level constant below)
from ctypes import (wintypes, byref, c_void_p, c_uint32, c_wchar_p,
                    c_ushort, c_ubyte, c_ulong, sizeof)
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_NO_WIN = 0x08000000  # CREATE_NO_WINDOW
_K32 = ctypes.windll.kernel32
_NTDLL = ctypes.windll.ntdll


# ══════════════════════════════════════════════════════════════════════════
# COM / WMI primitives (replaces Get-WmiObject / Get-CimInstance)
# ══════════════════════════════════════════════════════════════════════════

import threading as _threading

_com_local = _threading.local()   # per-thread: True once CoInitialize'd


def _com_ensure_initialized() -> None:
    """Initialize COM on this thread exactly ONCE per thread lifetime.

    v29.60b fix: every successful CoInitialize (including S_FALSE)
    requires a matching CoUninitialize — calling it per-request on
    long-lived threads accumulated COM refcounts without bound. A failed
    call (RPC_E_CHANGED_MODE — thread already MTA via the pool
    initializer) consumes nothing and is ignored.
    """
    if getattr(_com_local, 'inited', False):
        return
    try:
        import pythoncom  # type: ignore[import-not-found]
        pythoncom.CoInitialize()
    except Exception:
        pass   # already initialized in another apartment mode (MTA)
    _com_local.inited = True


def com_wmi_services(namespace: str = r'root\cimv2') -> Optional[Any]:
    """SWbemServices for `namespace` via COM Dispatch (MTA/STA safe).

    The exact native API PowerShell's Get-WmiObject wraps — but the
    Dispatch path also works on MTA threads. None when WMI unavailable."""
    try:
        _com_ensure_initialized()
        import win32com.client  # type: ignore[import-not-found]
        loc = win32com.client.Dispatch('WbemScripting.SWbemLocator')
        return loc.ConnectServer('.', namespace)
    except Exception as exc:
        _log.debug('com_wmi_services(%s): %s', namespace, exc)
        return None


def wmi_wql_dicts(namespace: str, wql: str,
                  fields: List[str]) -> List[Dict[str, Any]]:
    """Run WQL -> [{field: value, ...}] (None for missing fields).

    Replaces: Get-WmiObject -Namespace X -Class Y | Select A,B,C
              | ConvertTo-Json. Never raises; [] on failure."""
    out: List[Dict[str, Any]] = []
    try:
        svc = com_wmi_services(namespace)
        if svc is None:
            return out
        for item in svc.ExecQuery(wql):
            row: Dict[str, Any] = {}
            for f in fields:
                try:
                    row[f] = getattr(item, f)
                except Exception:
                    row[f] = None
            out.append(row)
    except Exception as exc:
        _log.debug('wmi_wql_dicts(%s): %s', wql[:80], exc)
    return out


def wmi_delete_instances(namespace: str, wql: str) -> bool:
    """Delete every WMI instance matching `wql` (replaces Remove-WmiObject).
    True when at least one deletion succeeded."""
    ok = False
    try:
        svc = com_wmi_services(namespace)
        if svc is None:
            return False
        for item in svc.ExecQuery(wql):
            try:
                item.Delete_()
                ok = True
            except Exception as exc:
                _log.debug('wmi_delete_instances item: %s', exc)
    except Exception as exc:
        _log.debug('wmi_delete_instances: %s', exc)
    return ok


def wmi_get_class_prop(namespace: str, wql: str, prop: str) -> List[Any]:
    """One property across instances (replaces Select-Object -ExpandProperty)."""
    vals: List[Any] = []
    try:
        svc = com_wmi_services(namespace)
        if svc is None:
            return vals
        for item in svc.ExecQuery(wql):
            try:
                vals.append(getattr(item, prop))
            except Exception:
                vals.append(None)
    except Exception as exc:
        _log.debug('wmi_get_class_prop: %s', exc)
    return vals


# ══════════════════════════════════════════════════════════════════════════
# Services / drivers (replaces Get-WmiObject Win32_Service/Win32_SystemDriver)
# ══════════════════════════════════════════════════════════════════════════

def get_services() -> List[Dict[str, Any]]:
    """[dict(Name, PathName, StartMode, Description, State)] Win32_Service."""
    return wmi_wql_dicts(
        r'root\cimv2',
        'SELECT Name, PathName, StartMode, Description, State '
        'FROM Win32_Service',
        ['Name', 'PathName', 'StartMode', 'Description', 'State'])


def get_system_drivers() -> List[Dict[str, Any]]:
    """[dict(Name, PathName, State, StartMode)] Win32_SystemDriver."""
    return wmi_wql_dicts(
        r'root\cimv2',
        'SELECT Name, PathName, State, StartMode FROM Win32_SystemDriver',
        ['Name', 'PathName', 'State', 'StartMode'])


def get_pnp_entities() -> List[Dict[str, Any]]:
    """[dict(Name, PNPClass, DeviceID, Status)] Win32_PnPEntity
    (replaces Get-PnpDevice)."""
    return wmi_wql_dicts(
        r'root\cimv2',
        'SELECT Name, PNPClass, DeviceID, Status FROM Win32_PnPEntity',
        ['Name', 'PNPClass', 'DeviceID', 'Status'])


def get_logical_disks() -> List[Dict[str, Any]]:
    """[dict(DeviceID, DriveType, PNPDeviceID)] Win32_LogicalDisk
    (replaces Get-WmiObject Win32_LogicalDisk)."""
    return wmi_wql_dicts(
        r'root\cimv2',
        'SELECT DeviceID, DriveType, PNPDeviceID FROM Win32_LogicalDisk',
        ['DeviceID', 'DriveType', 'PNPDeviceID'])


# ══════════════════════════════════════════════════════════════════════════
# DNS resolver cache (replaces Get-DnsClientCache) — dnsapi.dll
# ══════════════════════════════════════════════════════════════════════════

class _DNS_CACHE_ENTRY(ctypes.Structure):
    # Documented layout: chain ptr + two name pointers + type/len/flags
    _fields_ = [('psi', c_void_p),
                ('pszName', c_void_p),      # PWSTR (walk manually)
                ('pszName2', c_void_p),
                ('wType', c_ushort),
                ('wDataLength', c_ushort),
                ('dwFlags', c_uint32)]


def get_dns_cache_entries() -> List[Tuple[str, str]]:
    """Walk the DNS resolver cache natively via DnsGetCacheDataTable.

    Returns [(entry_name, record_data), ...] — same shape the old
    Get-DnsClientCache CSV parser produced (Data may be '' for some
    record types; DGA/beacon scoring only ever used the name).
    Best-effort; [] on failure."""
    out: List[Tuple[str, str]] = []
    try:
        dnsapi = ctypes.windll.dnsapi
        head = c_void_p()
        # BOOL DnsGetCacheDataTable(PVOID *ppEntry)
        if not dnsapi.DnsGetCacheDataTable(byref(head)) or not head.value:
            return out
        node = head.value
        seen = 0
        while node and seen < 4000:
            ent = _DNS_CACHE_ENTRY.from_address(node)
            if ent.pszName:
                try:
                    name = ctypes.wstring_at(ent.pszName)
                except Exception:
                    name = ''
                if name:
                    out.append((name, ''))
            nxt = ent.psi
            if not nxt or nxt == node:
                break
            node = nxt
            seen += 1
    except Exception as exc:
        _log.debug('get_dns_cache_entries: %s', exc)
    return out


# ══════════════════════════════════════════════════════════════════════════
# Event log (replaces Get-WinEvent) — wevtapi.dll, fully native
# ══════════════════════════════════════════════════════════════════════════

_EVT_NEXT_BATCH = 64


def evt_query_events(channel: str, xpath: str,
                     max_events: int = 50) -> List[Dict[str, Any]]:
    """Native event-log query (replaces Get-WinEvent -FilterHashtable).

    xpath is an event-log XPath, e.g. "*[System[(EventID=1102)]]".
    Returns [{'time': 'YYYY-MM-DD HH:MM:SS', 'id': int, 'level': str,
              'xml': full-event-xml}, ...]. Never raises; [] on failure."""
    out: List[Dict[str, Any]] = []
    try:
        import re as _re
        wevt = ctypes.windll.wevtapi
        EvtQuery = wevt.EvtQuery
        EvtQuery.restype = c_void_p
        EvtQuery.argtypes = [c_void_p, c_wchar_p, c_wchar_p, c_uint32]
        EvtNext = wevt.EvtNext
        EvtNext.restype = ctypes.c_int
        EvtNext.argtypes = [c_void_p, c_uint32,
                            ctypes.POINTER(c_void_p),
                            c_uint32, c_uint32,
                            ctypes.POINTER(wintypes.DWORD)]
        EvtRender = wevt.EvtRender
        EvtRender.restype = ctypes.c_int
        EvtRender.argtypes = [c_void_p, c_void_p, c_uint32, c_uint32,
                              c_void_p, ctypes.POINTER(wintypes.DWORD),
                              ctypes.POINTER(wintypes.DWORD)]
        EvtClose = wevt.EvtClose
        EvtClose.restype = ctypes.c_int
        EvtClose.argtypes = [c_void_p]

        # EvtQueryChannelPath flag: Path=channel, Query=XPath
        q = EvtQuery(None, channel, xpath, 0x00000100)
        if not q:
            return out
        try:
            buf = (c_void_p * _EVT_NEXT_BATCH)()
            returned = wintypes.DWORD(0)
            used = wintypes.DWORD(0)
            cnt = wintypes.DWORD(0)
            while len(out) < max_events:
                if not EvtNext(q, _EVT_NEXT_BATCH, buf, 5000, 0,
                               byref(returned)):
                    break
                for i in range(returned.value):
                    ev = buf[i]
                    if not ev:
                        continue
                    try:
                        # EvtRenderEventXml = 1: size probe, then render
                        used.value = 0
                        EvtRender(None, ev, 1, 0, None,
                                  byref(used), byref(cnt))
                        size = used.value
                        if not size:
                            continue
                        sbuf = ctypes.create_unicode_buffer(size + 1)
                        if EvtRender(None, ev, 1, (size + 1) * 2, sbuf,
                                     byref(used), byref(cnt)):
                            xml = sbuf.value or ''
                            tm = _re.search(
                                r"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)",
                                xml)
                            em = _re.search(
                                r"<EventID[^>]*>(\d+)</EventID>", xml)
                            lm = _re.search(
                                r"<Level[^>]*>(\d+)</Level>", xml)
                            if em:
                                out.append({
                                    'time': (tm.group(1)[:19]
                                             .replace('T', ' ')
                                             if tm else ''),
                                    'id': int(em.group(1)),
                                    'level': lm.group(1) if lm else '',
                                    'xml': xml})
                    finally:
                        EvtClose(ev)
        finally:
            EvtClose(q)
    except Exception as exc:
        _log.debug('evt_query_events(%s): %s', channel, exc)
    return out


def evt_count_events(channel: str, xpath: str,
                     max_events: int = 100) -> int:
    """Count matching events (replaces '(Get-WinEvent ...).Count')."""
    try:
        return len(evt_query_events(channel, xpath, max_events))
    except Exception:
        return 0


# ══════════════════════════════════════════════════════════════════════════
# Authenticode (replaces Get-AuthenticodeSignature) — wintrust.dll
# ══════════════════════════════════════════════════════════════════════════

_WINTRUST_ACTION_GENERIC_VERIFY_V2 = \
    '{00AAC56B-CD44-11D0-8222-00AEA04FB199}'


def authenticode_status(path: str) -> str:
    """'Valid' | 'NotSigned' | 'HashMismatch' | 'BadSignature' | 'Error'.

    Native WinVerifyTrust — the same call Get-AuthenticodeSignature makes.
    """
    try:
        import uuid as _uuid

        class GUID(ctypes.Structure):
            _fields_ = [('Data1', wintypes.DWORD),
                        ('Data2', wintypes.WORD),
                        ('Data3', wintypes.WORD),
                        ('Data4', c_ubyte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [('cbStruct', wintypes.DWORD),
                        ('pcwszFilePath', c_wchar_p),
                        ('hFile', c_void_p),
                        ('pgKnownSubject', c_void_p)]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [('cbStruct', wintypes.DWORD),
                        ('pPolicyCallbackData', c_void_p),
                        ('pSIPClientData', c_void_p),
                        ('dwUIChoice', wintypes.DWORD),
                        ('fdwRevocationChecks', wintypes.DWORD),
                        ('dwUnionChoice', wintypes.DWORD),
                        ('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                        ('dwStateAction', wintypes.DWORD),
                        ('hWVTStateData', c_void_p),
                        ('pwszURLReference', c_void_p),
                        ('dwProvFlags', wintypes.DWORD),
                        ('dwUIContext', wintypes.DWORD),
                        ('pSignatureSettings', c_void_p)]

        g = _uuid.UUID(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
        guid = GUID()
        guid.Data1 = g.time_low
        guid.Data2 = g.time_mid
        guid.Data3 = g.time_hi_version
        for i, b in enumerate(g.bytes[8:]):
            guid.Data4[i] = b

        fi = WINTRUST_FILE_INFO()
        fi.cbStruct = sizeof(WINTRUST_FILE_INFO)
        fi.pcwszFilePath = os.path.abspath(path)

        wtd = WINTRUST_DATA()
        wtd.cbStruct = sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = 2          # WTD_UI_NONE
        wtd.fdwRevocationChecks = 0
        wtd.dwUnionChoice = 1       # WTD_CHOICE_FILE
        wtd.pFile = ctypes.pointer(fi)

        _wt = ctypes.windll.wintrust
        rc = _wt.WinVerifyTrust(0, byref(guid), byref(wtd))
        rc_u = rc & 0xFFFFFFFF     # HRESULTs come back sign-extended
        if rc_u == 0:
            return 'Valid'
        if rc_u == 0x800B0100:
            return 'NotSigned'
        if rc_u == 0x80096010:
            return 'HashMismatch'
        if rc_u in (0x800B0109, 0x800B010A):
            return 'BadSignature'
        if rc_u == 0x800B0001:
            # TRUST_E_PROVIDER_UNKNOWN — observed live on Win11 with Smart
            # App Control in ON/Evaluation mode: the classic generic
            # WinVerifyTrust path is gated. Fall back to the native
            # catalog/embedded checks (how Windows itself trusts system
            # files — most Win11 system binaries are catalog-signed).
            return _authenticode_catalog_fallback(path)
        _log.debug('authenticode_status(%s): rc=0x%08X', path, rc_u)
        return 'Error'
    except Exception as exc:
        _log.debug('authenticode_status(%s): %s', path, exc)
        return 'Error'


def smart_app_control_state() -> int:
    """0=OFF 1=EVALUATION 2=ON (-1 = key absent/unsupported)."""
    try:
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SYSTEM\CurrentControlSet\Control\CI\Policy',
            0, winreg.KEY_READ)
        try:
            v, _ = winreg.QueryValueEx(k, 'VerifiedAndReputablePolicyState')
            return int(v)
        finally:
            winreg.CloseKey(k)
    except Exception:
        return -1


def reg_set_helper(subkey: str, name: str, value: Any,
                   vtype: Optional[int] = None) -> bool:
    """Public HKLM registry setter (DWORD/SZ auto). True on success."""
    try:
        k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, subkey)
        try:
            if vtype is None:
                vtype = (winreg.REG_DWORD if isinstance(value, int)
                         else winreg.REG_SZ)
            winreg.SetValueEx(k, name, 0, vtype, value)
            return True
        finally:
            winreg.CloseKey(k)
    except Exception as exc:
        _log.debug('reg_set_helper(%s, %s): %s', subkey, name, exc)
        return False


# Back-compat alias used by the hardening advisor
_reg_set_helper = reg_set_helper


def _authenticode_catalog_fallback(path: str) -> str:
    """Native catalog-hash + embedded-signature probe.

    Returns 'Valid' when the file's SHA1 hash is found in a catalog that
    exists on the system (catalogs are signed by Microsoft — presence is
    the same trust signal sigcheck uses), or when an embedded Authenticode
    signature exists. 'NotSigned' otherwise."""
    try:
        wt = ctypes.WinDLL('wintrust', use_last_error=True)
        crypt32 = ctypes.windll.crypt32
        # 1) embedded signature? CryptQueryObject (crypt32) with PKCS7 flags
        CERT_QUERY_CONTENT_FLAG_PKCS_SIGNED = 0x00000100 | 0x00000004
        hstore = c_void_p()
        hmsg = c_void_p()
        ok = crypt32.CryptQueryObject(
            1, os.path.abspath(path),        # CERT_QUERY_OBJECT_FILE
            CERT_QUERY_CONTENT_FLAG_PKCS_SIGNED,
            0x00000004,                      # CERT_QUERY_FORMAT_FLAG_BINARY
            0, None, None, None, byref(hstore), byref(hmsg), None)
        if ok and (hmsg.value or hstore.value):
            return 'Valid'                   # embedded Authenticode present
        # 2) catalog membership (covers catalog-signed system binaries)
        GENERIC_VERIFY_V2_GUID = (ctypes.c_ubyte * 16)(
            0x6B, 0xC5, 0xAA, 0x00, 0x44, 0xCD, 0xD0, 0x11,
            0x82, 0x22, 0x00, 0xAE, 0xA0, 0x4F, 0xB1, 0x99)
        hcat_admin = c_void_p()
        hcat_admin2 = c_void_p()   # v29.60b: *2 SHA256 context (both freed)
        GENERIC_VERIFY_V2_GUID_RAW = GENERIC_VERIFY_V2_GUID
        try:
            if not wt.CryptCATAdminAcquireContext(
                    byref(hcat_admin), GENERIC_VERIFY_V2_GUID, 0):
                # ERROR_ACCESS_DENIED on hardened/non-elevated systems — the
                # catalog admin API needs elevation (Downpour's normal
                # mode). Report 'Unknown', never claim 'NotSigned' for
                # files we could not evaluate.
                _log.debug('catalog fallback: AcquireContext denied err=%s',
                           ctypes.get_last_error())
                return 'Unknown'
        except Exception:
            return 'Unknown'
        try:
            k32 = ctypes.windll.kernel32
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 1
            OPEN_EXISTING = 3
            k32.CreateFileW.restype = c_void_p     # 64-bit handle, no trunc
            k32.CreateFileW.argtypes = [c_wchar_p, wintypes.DWORD,
                                        wintypes.DWORD, c_void_p,
                                        wintypes.DWORD, wintypes.DWORD,
                                        c_void_p]
            hfile = k32.CreateFileW(
                os.path.abspath(path), GENERIC_READ, FILE_SHARE_READ,
                None, OPEN_EXISTING, 0, None)
            if not hfile:
                # Cannot open the file (locked/denied) — that is NOT
                # evidence of "unsigned". v29.60b: report Unknown.
                return 'Unknown'
            try:
                hash_len = wintypes.DWORD(64)
                hash_buf = (c_ubyte * 64)()
                wt.CryptCATAdminCalcHashFromFileHandle.restype = \
                    ctypes.c_int
                wt.CryptCATAdminCalcHashFromFileHandle.argtypes = \
                    [c_void_p, ctypes.POINTER(wintypes.DWORD),
                     ctypes.POINTER(c_ubyte), wintypes.DWORD]
                # Modern servicing catalogs (Win10/11) are SHA256 — prefer
                # the hash-algorithm-aware *2 APIs, fall back to legacy
                # SHA1 context when unavailable.
                hctx = hcat_admin
                ok_hash = False
                try:
                    wt.CryptCATAdminAcquireContext2.restype = ctypes.c_int
                    wt.CryptCATAdminAcquireContext2.argtypes = \
                        [ctypes.POINTER(c_void_p), c_void_p, c_wchar_p,
                         c_void_p, wintypes.DWORD]
                    if wt.CryptCATAdminAcquireContext2(
                            byref(hcat_admin2), GENERIC_VERIFY_V2_GUID,
                            'SHA256', None, 0) and hcat_admin2.value:
                        wt.CryptCATAdminCalcHashFromFileHandle2.\
                            restype = ctypes.c_int
                        wt.CryptCATAdminCalcHashFromFileHandle2.\
                            argtypes = [c_void_p, c_wchar_p,
                                        ctypes.POINTER(wintypes.DWORD),
                                        ctypes.POINTER(c_ubyte),
                                        wintypes.DWORD]
                        if wt.CryptCATAdminCalcHashFromFileHandle2(
                                hcat_admin2, 'SHA256', byref(hash_len),
                                hash_buf, 0):
                            hctx = hcat_admin2
                            ok_hash = True
                except AttributeError:
                    pass   # pre-Win8 API set — legacy path only
                if not ok_hash:
                    ok_hash = bool(wt.CryptCATAdminCalcHashFromFileHandle(
                        hctx, byref(hash_len), hash_buf, 0))
                if not ok_hash:
                    _log.debug('catalog fallback: hash calc failed '
                               'err=%s len=%s', ctypes.get_last_error(),
                               hash_len.value)
                    # v29.60b: hash failure (e.g. NULL context after a
                    # denied AcquireContext) is UNKNOWN, not NotSigned.
                    return 'Unknown'
                _log.debug('catalog fallback: hash len=%s first=%s',
                           hash_len.value, hash_buf[0])
                wt.CryptCATAdminEnumCatalogFromHash.restype = c_void_p
                wt.CryptCATAdminEnumCatalogFromHash.argtypes = \
                    [c_void_p, ctypes.POINTER(c_ubyte), wintypes.DWORD,
                     wintypes.DWORD, c_void_p]
                hcat = wt.CryptCATAdminEnumCatalogFromHash(
                    hctx, hash_buf, hash_len, 0, None)
                if hcat:
                    wt.CryptCATAdminReleaseCatalogContext(hctx, hcat, 0)
                    return 'Valid'           # member of a system catalog
                return 'NotSigned'
            finally:
                k32.CloseHandle(hfile)
        finally:
            # v29.60b: release BOTH contexts (legacy + *2) — the *2 context
            # used to leak on every authenticode call.
            try:
                if hcat_admin2.value:
                    wt.CryptCATAdminReleaseContext(hcat_admin2, 0)
            except Exception:
                pass
            try:
                if hcat_admin.value:
                    wt.CryptCATAdminReleaseContext(hcat_admin, 0)
            except Exception:
                pass
    except Exception as exc:
        _log.debug('authenticode_catalog_fallback(%s): %s', path, exc)
        return 'Error'


# ══════════════════════════════════════════════════════════════════════════
# Speculation control (replaces Get-SpeculationControlSettings)
# ══════════════════════════════════════════════════════════════════════════

_SYSTEM_SPECULATION_CONTROL_INFORMATION = 201


def query_speculation_control() -> Dict[str, Any]:
    """KVA shadow / IBRS / SSBD via NtQuerySystemInformation(201) — the
    same syscall the SpeculationControl module uses. Registry fallback.
    Returns {'kva_shadow', 'ibrs', 'ssbd', 'detail'}."""
    result: Dict[str, Any] = {'kva_shadow': False, 'ibrs': False,
                              'ssbd': False, 'detail': ''}
    try:
        # SYSTEM_SPECULATION_CONTROL_INFORMATION: five ULONG bitfield words
        # (SpeculationControlFlags, KvaShadowFlags, IbrsFlags, SsbsFlags, ...)
        class SPEC_INFO(ctypes.Structure):
            _fields_ = [('Flags0', c_uint32),   # BpbEnabled etc.
                        ('Flags1', c_uint32),   # KvaShadow* bitflags
                        ('Flags2', c_uint32),   # IbrsPresent
                        ('Flags3', c_uint32),   # SsbdSupported
                        ('Flags4', c_uint32)]
        buf = SPEC_INFO()
        retlen = wintypes.ULONG(0)
        status = _NTDLL.NtQuerySystemInformation(
            _SYSTEM_SPECULATION_CONTROL_INFORMATION,
            byref(buf), sizeof(buf), byref(retlen))
        if status == 0:
            result['kva_shadow'] = bool(buf.Flags1 & 0x1)   # KvaShadowEnabled
            result['ibrs'] = bool(buf.Flags0 & 0x1) and \
                bool(buf.Flags2 & 0x1)   # BpbEnabled + IbrsPresent
            result['ssbd'] = bool(buf.Flags3 & 0x1)         # SsbdSupported
            result['detail'] = (
                f'KVA={int(result["kva_shadow"])} '
                f'IBRS={int(result["ibrs"])} '
                f'SSBD={int(result["ssbd"])}')
        else:
            import winreg
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Session Manager'
                r'\Memory Management', 0, winreg.KEY_READ)
            try:
                feats, _ = winreg.QueryValueEx(k, 'FeatureSettings')
                result['kva_shadow'] = bool(feats & 1)
                result['detail'] = f'FeatureSettings={feats}'
            finally:
                winreg.CloseKey(k)
    except Exception as exc:
        result['detail'] = f'native probe failed: {exc}'
    return result


def get_dep_policy() -> int:
    """0=off 1=optin 2=optout 3=alwayson (native GetSystemDEPPolicy)."""
    try:
        return int(_K32.GetSystemDEPPolicy())
    except Exception:
        return 0


# ══════════════════════════════════════════════════════════════════════════
# VPN phonebook (replaces Add/Remove-VpnConnection) — rasphone.pbk store
# ══════════════════════════════════════════════════════════════════════════

def _pbk_path(all_user: bool) -> str:
    if all_user:
        return os.path.expandvars(
            r'%ALLUSERSPROFILE%\Microsoft\Network\Connections'
            r'\Pbk\rasphone.pbk')
    return os.path.expandvars(
        r'%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk')


def ras_delete_entry(entry_name: str) -> bool:
    """Delete a VPN phonebook entry (replaces Remove-VpnConnection -Force)."""
    try:
        rc = ctypes.windll.rasapi32.RasDeleteEntryW(None, entry_name)
        return rc == 0
    except Exception as exc:
        _log.debug('ras_delete_entry(%s): %s', entry_name, exc)
        return False


def ras_set_entry(entry_name: str, host: str, tunnel: str = 'l2tp',
                  all_user: bool = True) -> bool:
    """Create/overwrite a VPN phonebook entry (replaces Add-VpnConnection).

    Writes the rasphone.pbk store — the exact same store the PowerShell
    cmdlet and the Windows Settings UI maintain — with sane defaults
    (MSChapv2 auth, MPPE required). `tunnel` in ('l2tp', 'sstp')."""
    try:
        pbk = _pbk_path(all_user)
        os.makedirs(os.path.dirname(pbk), exist_ok=True)
        section = f'[{entry_name}]'
        strategy = '3' if tunnel == 'l2tp' else '5'
        body = (
            f'[{entry_name}]\r\n'
            'Encoding=1\r\n'
            'Type=5\r\n'
            'DeviceType=vpn\r\n'
            f'DeviceName={host}\r\n'
            'PhoneBookID=E80A99A0-E2B7-4C88-8C42-AE5F1F0F4F1E\r\n'
            f'PhoneNumber={host}\r\n'
            'Authentication=5\r\n'
            'DataEncryption=8\r\n'
            'TunnelType=' + ('1' if tunnel == 'l2tp' else '2') + '\r\n'
            'UseRasCredentials=1\r\n'
            'TCPIP=1\r\n'
            'IPPriority=3\r\n'
            'PreviewDomain=1\r\n'
            'PreviewPhoneNumber=1\r\n'
            'ShowDialingProgress=1\r\n'
            'SecureLocalFiles=0\r\n'
            f'VpnStrategy={strategy}\r\n'
            '\r\n')
        existing = ''
        if os.path.isfile(pbk):
            try:
                existing = open(pbk, 'r', encoding='utf-8',
                                errors='replace').read()
            except Exception:
                existing = ''
        if section in existing:
            import re as _re
            pat = _re.compile(
                _re.escape(section) + r'.*?(?=\r?\n\[|$)', _re.S)
            new_content = pat.sub(body, existing, count=1)
        else:
            new_content = (existing.rstrip() + '\r\n\r\n' + body
                           if existing.strip() else body)
        import tempfile as _tf
        fd, tmp = _tf.mkstemp(dir=os.path.dirname(pbk), suffix='.pbk')
        with os.fdopen(fd, 'w', encoding='utf-8') as _f:
            _f.write(new_content)
        try:
            os.replace(tmp, pbk)
        except PermissionError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        # Verify RAS recognizes the entry (native validation)
        try:
            buf = ctypes.create_string_buffer(8192)
            devinfo = ctypes.create_string_buffer(16 + 264)
            dwDev = wintypes.DWORD(264)
            rc = ctypes.windll.rasapi32.RasGetEntryPropertiesW(
                None, entry_name, buf, wintypes.DWORD(8192),
                devinfo, byref(dwDev))
            if rc != 0:
                _log.debug('ras_set_entry verify rc=%s (entry written '
                           'anyway; rasdial is the final arbiter)', rc)
        except Exception:
            pass
        return True
    except Exception as exc:
        _log.debug('ras_set_entry(%s): %s', entry_name, exc)
        return False


# ══════════════════════════════════════════════════════════════════════════
# Defender preferences (replaces Get/Set-MpPreference) — WMI Defender ns
# ══════════════════════════════════════════════════════════════════════════

# HKLM\SOFTWARE\Microsoft\Windows Defender\<Subkey>\<Value> — the registry
# view the MpPreference cmdlets maintain (tamper protection still guards
# it; non-admin writes fail exactly like the PS cmdlet).
_DEFENDER_VALUES: Dict[str, Tuple[str, str]] = {
    'DisableRealtimeMonitoring': (r'Real-Time Protection',
                                  'DisableRealtimeMonitoring'),
    'MAPSReporting': (r'SpyNet', 'MAPSReporting'),
    'SubmitSamplesConsent': (r'SpyNet', 'SubmitSamplesConsent'),
    'PUAProtection': ('', 'PUAProtection'),
    'DisableIntrusionPreventionSystem': ('', 'DisableIntrusionPrevention'
                                         'System'),
    'EnableControlledFolderAccess':
        (r'Windows Defender Exploit Guard\Controlled Folder Access',
         'EnableControlledFolderAccess'),
}


def get_defender_pref_int(prop: str, default: Optional[int] = None) \
        -> Optional[int]:
    """Read an integer MpPreference property natively.

    Order: WMI root\\Microsoft\\Windows\\Defender MSFT_MpPreference, then
    the registry location above. `default` when unavailable."""
    try:
        rows = wmi_wql_dicts(r'root\Microsoft\Windows\Defender',
                             'SELECT * FROM MSFT_MpPreference', [prop])
        if rows and rows[0].get(prop) is not None:
            return int(rows[0][prop])
    except Exception:
        pass
    try:
        import winreg
        sub, val = _DEFENDER_VALUES.get(prop, ('', prop))
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            (rf'SOFTWARE\Microsoft\Windows Defender\{sub}').rstrip('\\'),
            0, winreg.KEY_READ)
        try:
            v, _ = winreg.QueryValueEx(key, val)
            return int(v)
        finally:
            winreg.CloseKey(key)
    except Exception:
        return default


def get_asr_rule_ids() -> List[str]:
    """Configured ASR rule GUIDs (replaces Get-MpPreference |
    Select AttackSurfaceReductionRules_Ids). WMI first, then the GPO
    Policies registry (which Defender honors)."""
    try:
        rows = wmi_wql_dicts(r'root\Microsoft\Windows\Defender',
                             'SELECT AttackSurfaceReductionRules_Ids '
                             'FROM MSFT_MpPreference',
                             ['AttackSurfaceReductionRules_Ids'])
        if rows and rows[0].get('AttackSurfaceReductionRules_Ids'):
            raw = rows[0]['AttackSurfaceReductionRules_Ids']
            if isinstance(raw, (list, tuple)):
                return [str(x) for x in raw]
            return [s.strip() for s in str(raw).split(',') if s.strip()]
    except Exception:
        pass
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SOFTWARE\Policies\Microsoft\Windows Defender\Windows '
            r'Defender Exploit Guard\ASR\Rules', 0, winreg.KEY_READ)
        try:
            ids: List[str] = []
            i = 0
            while True:
                try:
                    name, _v, _t = winreg.EnumValue(key, i)
                    if name:
                        ids.append(name)
                    i += 1
                except OSError:
                    break
            return ids
        finally:
            winreg.CloseKey(key)
    except Exception:
        return []


def defender_revert_controlled_folder_access() -> bool:
    """Disable Controlled Folder Access natively (replaces
    Remove-MpPreference -ControlledFolderAccessDisabled)."""
    ok = False
    try:
        import winreg
        subs = (r'SOFTWARE\Microsoft\Windows Defender\Windows Defender '
                r'Exploit Guard\Controlled Folder Access',
                r'SOFTWARE\Microsoft\Windows Defender\Windows Defender'
                r'\Exploit Guard\Controlled Folder Access')
        for sub in subs:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub, 0,
                                     winreg.KEY_SET_VALUE)
                try:
                    winreg.SetValueEx(key, 'EnableControlledFolderAccess',
                                      0, winreg.REG_DWORD, 0)
                    ok = True
                finally:
                    winreg.CloseKey(key)
            except Exception:
                continue
    except Exception as exc:
        _log.debug('defender_revert_cfa: %s', exc)
    return ok


# ══════════════════════════════════════════════════════════════════════════
# Clipboard (replaces Get-Clipboard) — user32, no COM needed
# ══════════════════════════════════════════════════════════════════════════

def get_clipboard_text() -> str:
    """Clipboard text (CF_UNICODETEXT) or ''. Native user32 calls."""
    try:
        CF_UNICODETEXT = 13
        _U32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        _U32.OpenClipboard.restype = ctypes.c_int
        _U32.OpenClipboard.argtypes = [c_void_p]
        if not _U32.OpenClipboard(None):
            return ''
        try:
            h = _U32.GetClipboardData(CF_UNICODETEXT)
            if not h:
                return ''
            k32.GlobalLock.restype = c_void_p
            k32.GlobalLock.argtypes = [c_void_p]
            k32.GlobalUnlock.restype = ctypes.c_int
            k32.GlobalUnlock.argtypes = [c_void_p]
            k32.GlobalSize.restype = ctypes.c_size_t
            k32.GlobalSize.argtypes = [c_void_p]
            ptr = k32.GlobalLock(h)
            if not ptr:
                return ''
            try:
                # Bound the read with GlobalSize — wstring_at without a
                # length walks past the allocation (access violation seen
                # live). Text is NUL-terminated within the block.
                size = k32.GlobalSize(h) or 0
                if not size:
                    return ''
                raw = ctypes.wstring_at(ptr, size // 2)
                return raw.split('\x00', 1)[0]
            finally:
                k32.GlobalUnlock(h)
        finally:
            _U32.CloseClipboard()
    except Exception as exc:
        _log.debug('get_clipboard_text: %s', exc)
        return ''


# ══════════════════════════════════════════════════════════════════════════
# NTFS Alternate Data Streams (replaces Get-Item -Stream *) — kernel32
# ══════════════════════════════════════════════════════════════════════════

def find_ads(path: str) -> List[Tuple[str, int]]:
    """[(stream_name, size)] of every stream on `path`, excluding the
    default :$DATA and Zone.Identifier. Native FindFirstStreamW walk."""
    out: List[Tuple[str, int]] = []
    try:
        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [('llStreamSize', ctypes.c_longlong),
                        ('cStreamName', ctypes.c_wchar * 296)]
        fdata = WIN32_FIND_STREAM_DATA()
        k32 = ctypes.windll.kernel32
        # restype MUST be c_void_p — the default c_int truncates the 64-bit
        # handle on x64, and the truncated value crashes FindNextStreamW
        # (live access violation). Args stay loosely typed.
        k32.FindFirstStreamW.restype = c_void_p
        k32.FindFirstStreamW.argtypes = [c_wchar_p, wintypes.DWORD,
                                         ctypes.POINTER(
                                             WIN32_FIND_STREAM_DATA),
                                         wintypes.DWORD]
        k32.FindNextStreamW.restype = ctypes.c_int
        k32.FindNextStreamW.argtypes = [c_void_p,
                                        ctypes.POINTER(
                                            WIN32_FIND_STREAM_DATA)]
        k32.FindClose.restype = ctypes.c_int
        k32.FindClose.argtypes = [c_void_p]
        h = k32.FindFirstStreamW(os.path.abspath(path), 0, byref(fdata), 0)
        if not h or h == -1 or h == 0xFFFFFFFFFFFFFFFF:
            return out
        try:
            while True:
                nm = fdata.cStreamName
                base = nm.rsplit(':', 1)[0] if nm else ''
                if nm and base not in ('', 'Zone.Identifier'):
                    out.append((nm, int(fdata.llStreamSize)))
                if not k32.FindNextStreamW(h, byref(fdata)):
                    break
        finally:
            k32.FindClose(h)
    except Exception as exc:
        _log.debug('find_ads(%s): %s', path, exc)
    return out


# ══════════════════════════════════════════════════════════════════════════
# Minidump (replaces the Out-Minidump PS + Add-Type block) — dbghelp.dll
# ══════════════════════════════════════════════════════════════════════════

def write_minidump(target_pid: int, dump_path: str) -> Tuple[bool, str]:
    """Write a process minidump natively via MiniDumpWriteDump.
    (True, path) on success; (False, reason) otherwise."""
    try:
        import win32api  # type: ignore[import-not-found]
        import win32process  # type: ignore[import-not-found]
        import win32con  # type: ignore[import-not-found]
        perms = win32con.PROCESS_QUERY_INFORMATION | \
            win32con.PROCESS_VM_READ
        hproc = win32api.OpenProcess(perms, False, int(target_pid))
        if not hproc:
            return False, 'OpenProcess failed (need admin?)'
        try:
            hfile = win32api.CreateFile(
                dump_path, win32con.GENERIC_WRITE, 0, None,
                win32con.CREATE_ALWAYS, 0, None)
            try:
                MiniDumpNormal = 0x00000000
                ok = ctypes.windll.dbghelp.MiniDumpWriteDump(
                    int(hproc), int(target_pid), int(hfile),
                    MiniDumpNormal, None, None, None)
                if ok and os.path.isfile(dump_path) and \
                        os.path.getsize(dump_path) > 0:
                    return True, f'Memory dumped -> {os.path.basename(dump_path)}'
                return False, 'MiniDumpWriteDump failed'
            finally:
                try:
                    win32api.CloseHandle(hfile)
                except Exception:
                    pass
        finally:
            try:
                win32api.CloseHandle(hproc)
            except Exception:
                pass
    except Exception as exc:
        return False, f'Dump error: {exc}'


# ══════════════════════════════════════════════════════════════════════════
# Secure Boot (replaces Confirm-SecureBootUEFI) — registry State value
# ══════════════════════════════════════════════════════════════════════════

def secure_boot_enabled() -> bool:
    """True when UEFI Secure Boot is ON (the same value
    Confirm-SecureBootUEFI reads). Non-UEFI systems return False."""
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SYSTEM\CurrentControlSet\Control\SecureBoot\State',
            0, winreg.KEY_READ)
        try:
            v, _ = winreg.QueryValueEx(k, 'UEFISecureBootEnabled')
            return bool(v)
        finally:
            winreg.CloseKey(k)
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════
# PowerShell execution policy (replaces Get-ExecutionPolicy / the
# Set-ExecutionPolicy hardening action) — the registry value the cmdlet
# itself maintains (HKLM MachineGroupPolicy > HKLM MachinePolicy >
# HKLM ShellIds > HKCU ShellIds).
# ══════════════════════════════════════════════════════════════════════════

_EXEC_POLICY_KEYS = (
    (winreg.HKEY_LOCAL_MACHINE,
     r'SOFTWARE\Policies\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'),
    (winreg.HKEY_LOCAL_MACHINE,
     r'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'),
    (winreg.HKEY_CURRENT_USER,
     r'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'),
)


def get_powershell_execution_policy() -> str:
    """Current machine-scope execution policy string ('' = undefined)."""
    import winreg
    for hive, sub in _EXEC_POLICY_KEYS:
        try:
            k = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
            try:
                v, _ = winreg.QueryValueEx(k, 'ExecutionPolicy')
                return str(v)
            finally:
                winreg.CloseKey(k)
        except OSError:
            continue
    return ''


def set_powershell_execution_policy(policy: str = 'RemoteSigned') -> bool:
    """Set machine-scope execution policy natively (replaces
    Set-ExecutionPolicy RemoteSigned -Force)."""
    import winreg
    for hive, sub in _EXEC_POLICY_KEYS[1:2]:   # HKLM ShellIds = LocalMachine
        try:
            k = winreg.CreateKey(hive, sub)
            try:
                winreg.SetValueEx(k, 'ExecutionPolicy', 0,
                                  winreg.REG_SZ, policy)
                return True
            finally:
                winreg.CloseKey(k)
        except OSError:
            continue
    return False


# ══════════════════════════════════════════════════════════════════════════
# Windows Updates (replaces the PS COM invocation) — native COM Dispatch
# ══════════════════════════════════════════════════════════════════════════

def count_pending_updates() -> int:
    """Count pending Windows Updates via the native COM Microsoft.Update
    Session API (slow — call off the UI thread)."""
    try:
        _com_ensure_initialized()
        import win32com.client  # type: ignore[import-not-found]
        session = win32com.client.Dispatch('Microsoft.Update.Session')
        searcher = session.CreateUpdateSearcher()
        res = searcher.Search("IsInstalled=0 and IsHidden=0")
        return int(res.Updates.Count)
    except Exception as exc:
        _log.debug('count_pending_updates: %s', exc)
        return -1


# ══════════════════════════════════════════════════════════════════════════
# .lnk shortcut target (replaces WScript.Shell via PS New-Object) — the
# SAME WScript.Shell COM object, dispatched directly from Python
# ══════════════════════════════════════════════════════════════════════════

def lnk_target(lnk_path: str) -> str:
    """Resolve a .lnk shortcut's target path ('' on failure)."""
    try:
        _com_ensure_initialized()
        import win32com.client  # type: ignore[import-not-found]
        shell = win32com.client.Dispatch('WScript.Shell')
        sc = shell.CreateShortCut(os.path.abspath(lnk_path))
        return str(sc.Targetpath or '')
    except Exception as exc:
        _log.debug('lnk_target(%s): %s', lnk_path, exc)
        return ''


# ══════════════════════════════════════════════════════════════════════════
# Defender MpPreference-command translators (native replacements for the
# Add-MpPreference / Set-MpPreference cmdlets) — v29.60
# ══════════════════════════════════════════════════════════════════════════

def defender_ps_native(ps_cmd: str) -> Tuple[bool, str]:
    """Apply Add-MpPreference / Set-MpPreference commands via their
    underlying registry operations. Returns (ok, detail)."""
    import re as _re
    ok_all = True
    notes = []
    for part in [p.strip() for p in (ps_cmd or '').split(';') if p.strip()]:
        low = part.lower()
        handled = True
        try:
            if low.startswith('add-mppreference') or \
                    ('attacksurfacereductionrules_ids' in low and
                     'add-' in low):
                ids = _re.findall(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{27}', part)
                act_tokens = (part.split('_Actions', 1)[1].split(',')
                              if '_Actions' in part else ['Enabled'])
                for i, rid in enumerate(ids):
                    act = act_tokens[i % len(act_tokens)].strip()
                    act = act.split()[0] if act.split() else 'Enabled'
                    val = {'Enabled': 1, 'AuditMode': 2, 'Warn': 6,
                           'Disabled': 0}.get(act, 1)
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Policies\Microsoft\Windows Defender'
                        r'\Windows Defender Exploit Guard\ASR\Rules',
                        rid, val, winreg.REG_SZ)
                notes.append(f'ASR rules x{len(ids)} (reg)')
            elif 'set-mppreference' in low:
                if 'enablenetworkprotection' in low:
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Policies\Microsoft\Windows Defender'
                        r'\Windows Defender Exploit Guard\Network'
                        r' Protection', 'EnableNetworkProtection', 1)
                    notes.append('NetProt=1')
                elif 'cloudblocklevel' in low:
                    lvl = 'High' if 'high' in low else 'Default'
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Policies\Microsoft\Windows Defender'
                        r'\MpEngine', 'MpCloudBlockLevel', lvl, winreg.REG_SZ)
                    notes.append(f'Cloud={lvl}')
                elif 'cloudextendedtimeout' in low:
                    import re as _re2
                    m = _re2.search(r'CloudExtendedTimeout\s+(\d+)', part,
                                    _re2.IGNORECASE)
                    sec = int(m.group(1)) if m else 50
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Policies\Microsoft\Windows Defender'
                        r'\MpEngine', 'MpCloudExtendedTimeout', sec)
                    notes.append(f'CloudTimeout={sec}')
                elif 'enablecontrolledfolderaccess' in low:
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Microsoft\Windows Defender\Windows'
                        r' Defender Exploit Guard\Controlled Folder Access',
                        'EnableControlledFolderAccess', 1)
                    notes.append('CFA=1')
                elif 'signatureupdateinterval' in low:
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Policies\Microsoft\Windows Defender'
                        r'\Signature Updates', 'SignatureUpdateInterval', 1)
                    notes.append('SigUpdate=1')
                elif 'puaprotection' in low:
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Microsoft\Windows Defender',
                        'PUAProtection', 1)
                    notes.append('PUA=1')
                elif 'mapsreporting' in low:
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Microsoft\Windows Defender\SpyNet',
                        'MAPSReporting', 2)
                    notes.append('MAPS=2')
                elif 'submitsamplesconsent' in low:
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Microsoft\Windows Defender\SpyNet',
                        'SubmitSamplesConsent', 1)
                    notes.append('Samples=1')
                elif 'disablerealtimemonitoring' in low:
                    want = 0 if ('false' in low) else 1
                    ok_all &= reg_set_helper(
                        r'SOFTWARE\Microsoft\Windows Defender\Real-Time'
                        r' Protection', 'DisableRealtimeMonitoring', want)
                    notes.append(f'RTP={want}')
                else:
                    handled = False
            else:
                handled = False
        except Exception as exc:
            ok_all = False
            notes.append(f'err:{exc}')
            handled = True
        if not handled:
            ok_all = False
            notes.append(f'unsupported:{part[:50]}')
    return (ok_all, '; '.join(notes) or 'applied')


def extra_ps_native(ps_cmd: str) -> Tuple[bool, str]:
    """Native applier for the remaining command families (dism, SMB
    config, service control, PS registry paths). Returns (ok, detail)."""
    import re as _re
    ok_all = True
    notes = []
    for part in [p.strip() for p in (ps_cmd or '').split(';') if p.strip()]:
        low = part.lower()
        try:
            if 'disable-windowsoptionalfeature' in low:
                m = _re.search(r'-FeatureName\s+([^\s;]+)', part,
                               _re.IGNORECASE)
                fname = m.group(1) if m else ''
                import subprocess as _sp
                r = _sp.run(
                    ['dism', '/online', '/disable-feature',
                     f'/featurename:{fname}', '/norestart'],
                    capture_output=True, text=True, timeout=600,
                    creationflags=_NO_WIN)
                ok_all &= (r.returncode == 0)
                notes.append(f'dism:{fname}:rc{r.returncode}')
            elif 'set-smbclientconfiguration' in low:
                ok_all &= reg_set_helper(
                    r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation'
                    r'\Parameters', 'RequireSecuritySignature', 1)
                notes.append('SMB-client sig=1')
            elif 'set-smbserverconfiguration' in low:
                name, val = (('SMB1', 0)
                             if ('enablesmb1protocol' in low and
                                 '$false' in low)
                             else ('RequireSecuritySignature', 1))
                ok_all &= reg_set_helper(
                    r'SYSTEM\CurrentControlSet\Services\LanmanServer'
                    r'\Parameters', name, val)
                notes.append(f'SMB-server {name}={val}')
            elif 'stop-service' in low or 'set-service' in low:
                import subprocess as _sp
                m = _re.search(r'-Name\s+([^\s;]+)', part, _re.IGNORECASE)
                svc = m.group(1) if m else ''
                if svc:
                    _sp.run(['sc', 'stop', svc], capture_output=True,
                            timeout=15, creationflags=_NO_WIN)
                    _sp.run(['sc', 'config', svc, 'start=', 'disabled'],
                            capture_output=True, timeout=15,
                            creationflags=_NO_WIN)
                    notes.append(f'{svc} stopped+disabled')
            elif 'set-itemproperty' in low:
                mpath = _re.search(r'-Path\s+"?([^"\s;]+)', part,
                                   _re.IGNORECASE)
                mname = _re.search(r'-Name\s+([^\s;]+)', part,
                                   _re.IGNORECASE)
                mval = _re.search(r'-Value\s+([^\s;-]+)', part,
                                  _re.IGNORECASE)
                if mpath and mname and mval:
                    rp = mpath.group(1)
                    hive = (winreg.HKEY_LOCAL_MACHINE
                            if rp.upper().startswith('HKLM')
                            else winreg.HKEY_CURRENT_USER)
                    sub = rp.split('\\', 1)[1] if '\\' in rp else rp
                    k = winreg.CreateKey(hive, sub)
                    try:
                        v = mval.group(1)
                        num = int(v) if v.lstrip('-').isdigit() else v
                        winreg.SetValueEx(
                            k, mname.group(1), 0,
                            winreg.REG_DWORD if isinstance(num, int)
                            else winreg.REG_SZ, num)
                        notes.append(f'{mname.group(1)}={num}')
                    finally:
                        winreg.CloseKey(k)
                else:
                    ok_all = False
                    notes.append('Set-ItemProperty parse error')
            else:
                ok_all = False
                notes.append(f'unsupported:{part[:50]}')
        except Exception as exc:
            ok_all = False
            notes.append(f'err:{exc}')
    return (ok_all, '; '.join(notes) or 'applied')







