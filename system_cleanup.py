"""
Downpour v29 Titanium — System Cleanup Tool
=============================================
Restores falsely quarantined files, purges false-positive DB entries,
removes stale firewall rules, and resets threat counters.

Run as Administrator for full functionality.

Usage:
    python system_cleanup.py              # Interactive menu
    python system_cleanup.py --auto       # Auto-fix everything
    python system_cleanup.py --restore    # Restore quarantined files only
    python system_cleanup.py --purge-db   # Purge false positive DB entries only
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "downpour_data" / "titanium.db"
QUARANTINE_DIR = Path(__file__).parent / "downpour_data" / "quarantine" / "locked"

# ---------------------------------------------------------------------------
# Known false-positive patterns
# ---------------------------------------------------------------------------

# Files that should NEVER have been quarantined
WINDOWS_DEFENDER_PATHS = (
    '\\microsoft\\windows defender\\',
    '\\program files\\windows defender\\',
    '\\windows defender advanced threat protection\\',
)

WINDOWS_DEFENDER_FILES = {
    'mpoav.dll', 'mpcmdrun.exe', 'mpclient.dll', 'mpdetours.dll',
    'mpdetourscopyaccelerator.dll', 'endpointdlp.dll', 'mdediag.dll',
    'msmpeng.exe', 'nissrv.exe', 'mpengine.dll', 'mpsigstub.exe',
    'mpsvc.dll', 'mpnotify.exe', 'mpdlpcmd.exe',
    'securityhealthservice.exe', 'smartscreen.exe',
}

# Legitimate Windows services that should not be in threat_events
SAFE_SERVICE_PATHS = (
    '\\systemroot\\', '\\windows\\', '\\system32\\',
    '\\driverstore\\', 'svchost.exe', '\\program files\\',
    '\\program files (x86)\\',
)

# Built-in Windows virtual adapters that are not botnet phantom devices
SAFE_VIRTUAL_ADAPTERS = {
    'teredo', '6to4', 'isatap', 'ip-https', 'iphttps',
    'pseudo-interface', 'loopback', 'bluetooth', 'hyper-v',
    'vmware', 'virtualbox', 'docker', 'wsl', 'vpn',
    'wi-fi direct', 'microsoft',
}


def banner(text: str):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# 1. Restore falsely quarantined files
# ---------------------------------------------------------------------------

def restore_quarantined_files(db: sqlite3.Connection) -> int:
    """Restore files that were falsely quarantined (e.g., Windows Defender)."""
    banner("RESTORING FALSELY QUARANTINED FILES")

    rows = db.execute("SELECT id, original_path, quarantine_path, metadata "
                      "FROM quarantine WHERE restored = 0").fetchall()

    restored = 0
    for row_id, orig_path, q_path, metadata in rows:
        orig_lower = orig_path.lower()
        fname = os.path.basename(orig_path).lower()

        # Check if this is a known false positive
        is_false_positive = False
        reason = ""

        if fname in WINDOWS_DEFENDER_FILES:
            is_false_positive = True
            reason = f"Windows Defender component: {fname}"
        elif any(wd in orig_lower for wd in WINDOWS_DEFENDER_PATHS):
            is_false_positive = True
            reason = f"Windows Defender path: {orig_path}"

        if not is_false_positive:
            print(f"  [SKIP] {os.path.basename(orig_path)} — not a known FP, leaving quarantined")
            continue

        print(f"  [RESTORE] {reason}")
        print(f"    FROM: {q_path}")
        print(f"    TO:   {orig_path}")

        # Restore the file
        if os.path.exists(q_path):
            try:
                # Ensure parent directory exists
                os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                shutil.move(q_path, orig_path)
                db.execute("UPDATE quarantine SET restored = 1 WHERE id = ?", (row_id,))
                db.commit()
                restored += 1
                print(f"    [OK] Restored successfully")
            except PermissionError:
                print(f"    [FAIL] Permission denied — run as Administrator")
            except Exception as e:
                print(f"    [FAIL] {e}")
        else:
            print(f"    [WARN] Quarantine file not found at {q_path}")
            # Still mark as restored so it doesn't keep appearing
            db.execute("UPDATE quarantine SET restored = 1 WHERE id = ?", (row_id,))
            db.commit()

    # Also undo firewall blocks for restored files
    if restored > 0:
        print(f"\n  Cleaning up firewall rules for restored files...")
        _remove_downpour_firewall_rules()

    print(f"\n  Result: {restored} files restored out of {len(rows)} quarantined")
    return restored


# ---------------------------------------------------------------------------
# 2. Purge false positive DB entries
# ---------------------------------------------------------------------------

def purge_false_positive_db_entries(db: sqlite3.Connection) -> dict:
    """Remove false positive entries from threat database tables."""
    banner("PURGING FALSE POSITIVE DATABASE ENTRIES")
    stats = {}

    # 2a. threat_events — remove ServiceCreation for known safe services
    try:
        # Count before
        before = db.execute("SELECT COUNT(*) FROM threat_events "
                            "WHERE type = 'ServiceCreation'").fetchone()[0]

        # Get all ServiceCreation events and check each one
        rows = db.execute("SELECT id, detail FROM threat_events "
                          "WHERE type = 'ServiceCreation'").fetchall()
        safe_ids = []
        for row_id, detail in rows:
            detail_lower = (detail or '').lower()
            if any(sp in detail_lower for sp in SAFE_SERVICE_PATHS) or not detail.strip():
                safe_ids.append(row_id)

        # Delete in batches
        for i in range(0, len(safe_ids), 500):
            batch = safe_ids[i:i+500]
            placeholders = ','.join('?' * len(batch))
            db.execute(f"DELETE FROM threat_events WHERE id IN ({placeholders})", batch)
        db.commit()

        after = db.execute("SELECT COUNT(*) FROM threat_events "
                           "WHERE type = 'ServiceCreation'").fetchone()[0]
        removed = before - after
        stats['service_creation_removed'] = removed
        print(f"  [OK] threat_events: Removed {removed} safe ServiceCreation entries "
              f"({after} suspicious remain)")
    except Exception as e:
        print(f"  [ERR] threat_events cleanup failed: {e}")

    # 2b. worm_events — remove conhost.exe share_propagation false positives
    try:
        before = db.execute("SELECT COUNT(*) FROM worm_events").fetchone()[0]
        # Remove entries where file_path contains conhost.exe or other system processes
        safe_worm_patterns = [
            '%conhost.exe%', '%csrss.exe%', '%svchost.exe%',
            '%lsass.exe%', '%services.exe%', '%explorer.exe%',
            '%dwm.exe%', '%sihost.exe%',
        ]
        for pattern in safe_worm_patterns:
            db.execute("DELETE FROM worm_events WHERE file_path LIKE ?", (pattern,))

        # Remove network_scanning events with low confidence
        db.execute("DELETE FROM worm_events WHERE event_type = 'network_scanning' "
                   "AND confidence <= 0.6")
        db.commit()

        after = db.execute("SELECT COUNT(*) FROM worm_events").fetchone()[0]
        removed = before - after
        stats['worm_events_removed'] = removed
        print(f"  [OK] worm_events: Removed {removed} false positive entries "
              f"({after} remain)")
    except Exception as e:
        print(f"  [ERR] worm_events cleanup failed: {e}")

    # 2c. memory_injection_events — clear Google Play Games false positives
    try:
        before = db.execute("SELECT COUNT(*) FROM memory_injection_events").fetchone()[0]
        # Known false positives: legitimate installers from Edge downloads
        safe_injection_patterns = [
            '%Install-GooglePlayGames%', '%microsoftedgedownloads%',
        ]
        for pattern in safe_injection_patterns:
            db.execute("DELETE FROM memory_injection_events "
                       "WHERE evidence LIKE ?", (pattern,))
        db.commit()
        after = db.execute("SELECT COUNT(*) FROM memory_injection_events").fetchone()[0]
        removed = before - after
        stats['injection_events_removed'] = removed
        print(f"  [OK] memory_injection_events: Removed {removed} false positives "
              f"({after} remain)")
    except Exception as e:
        print(f"  [ERR] memory_injection_events cleanup failed: {e}")

    # 2d. threat_families — reduce inflated counts for overly broad signatures
    try:
        # Get families with suspiciously generic signatures
        rows = db.execute("SELECT id, name, count FROM threat_families "
                          "ORDER BY count DESC").fetchall()
        removed_families = 0
        for fam_id, fam_name, count in rows:
            # "Shellcode Detected" with count 4871 is clearly false positives
            # Same for "Packed/Encrypted" catching normal compressed files
            if fam_name in ('Shellcode Detected', 'Packed/Encrypted') and count > 100:
                db.execute("DELETE FROM threat_families WHERE id = ?", (fam_id,))
                removed_families += 1
                print(f"  [OK] Removed inflated threat family: '{fam_name}' (count={count})")

        # Remove threat_history entries that reference deleted families
        db.execute("DELETE FROM threat_history WHERE family_id NOT IN "
                   "(SELECT id FROM threat_families)")
        db.commit()
        stats['families_removed'] = removed_families
    except Exception as e:
        print(f"  [ERR] threat_families cleanup failed: {e}")

    return stats


# ---------------------------------------------------------------------------
# 3. Remove Downpour-created firewall rules
# ---------------------------------------------------------------------------

def _remove_downpour_firewall_rules():
    """Remove firewall rules created by Downpour (DOWNPOUR_ISOLATE_*, DOWNPOUR_BLOCK_*)."""
    try:
        # List all firewall rules with DOWNPOUR prefix
        r = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
             'name=all', 'dir=out'],
            capture_output=True, text=True, timeout=15,
            creationflags=0x08000000)

        rules_to_remove = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith('Rule Name:'):
                name = line.split(':', 1)[1].strip()
                if name.startswith(('DOWNPOUR_ISOLATE_', 'DOWNPOUR_BLOCK_')):
                    rules_to_remove.append(name)

        removed = 0
        for rule in rules_to_remove:
            try:
                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule}'],
                    capture_output=True, timeout=10,
                    creationflags=0x08000000)
                removed += 1
                print(f"    Removed firewall rule: {rule}")
            except Exception:
                pass

        if removed:
            print(f"  [OK] Removed {removed} Downpour firewall rules")
        else:
            print(f"  [OK] No Downpour firewall rules found")
    except Exception as e:
        print(f"  [ERR] Firewall cleanup failed: {e}")


# ---------------------------------------------------------------------------
# 4. Reset DNS and network (remove sinkhole entries)
# ---------------------------------------------------------------------------

def clean_hosts_file():
    """Remove Downpour-added entries from the hosts file."""
    banner("CLEANING HOSTS FILE")
    hosts_path = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts'

    try:
        with open(hosts_path, 'r') as f:
            lines = f.readlines()

        clean_lines = []
        removed = 0
        for line in lines:
            # Remove lines added by Downpour (DNS sinkhole entries)
            if '# DOWNPOUR' in line or '# downpour' in line:
                removed += 1
                continue
            clean_lines.append(line)

        if removed:
            with open(hosts_path, 'w') as f:
                f.writelines(clean_lines)
            print(f"  [OK] Removed {removed} Downpour-added hosts entries")
        else:
            print(f"  [OK] No Downpour entries found in hosts file")
    except PermissionError:
        print(f"  [FAIL] Permission denied — run as Administrator")
    except Exception as e:
        print(f"  [ERR] {e}")


# ---------------------------------------------------------------------------
# 5. Network reset
# ---------------------------------------------------------------------------

def reset_network():
    """Flush DNS cache, reset ARP table."""
    banner("RESETTING NETWORK STATE")

    cmds = [
        (['ipconfig', '/flushdns'], "Flushing DNS cache"),
        (['netsh', 'interface', 'ip', 'delete', 'arpcache'], "Clearing ARP cache"),
    ]

    for cmd, desc in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=10, creationflags=0x08000000)
            status = "[OK]" if r.returncode == 0 else "[WARN]"
            print(f"  {status} {desc}")
        except Exception as e:
            print(f"  [ERR] {desc}: {e}")


# ---------------------------------------------------------------------------
# 6. Summary report
# ---------------------------------------------------------------------------

def generate_report(stats: dict, restored: int):
    """Print a cleanup summary."""
    banner("CLEANUP SUMMARY")

    print(f"  Files restored from quarantine:     {restored}")
    print(f"  ServiceCreation FPs removed:        {stats.get('service_creation_removed', 0)}")
    print(f"  Worm event FPs removed:             {stats.get('worm_events_removed', 0)}")
    print(f"  Memory injection FPs removed:       {stats.get('injection_events_removed', 0)}")
    print(f"  Threat families cleaned:            {stats.get('families_removed', 0)}")
    print()
    print("  IMPORTANT: If Windows Defender was restored, restart your PC")
    print("  to ensure Defender services start properly.")
    print()
    print(f"  Cleanup completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print()
    print("  DOWNPOUR v29 TITANIUM — SYSTEM CLEANUP TOOL")
    print("  ============================================")
    print()

    if not DB_PATH.exists():
        print(f"  [ERR] Database not found: {DB_PATH}")
        return

    db = sqlite3.connect(str(DB_PATH))

    auto = '--auto' in sys.argv
    restore_only = '--restore' in sys.argv
    purge_only = '--purge-db' in sys.argv

    if not (auto or restore_only or purge_only):
        # Interactive menu
        print("  Options:")
        print("    1. Full cleanup (restore files + purge DB + clean network)")
        print("    2. Restore quarantined files only")
        print("    3. Purge false positive DB entries only")
        print("    4. Clean network (hosts, firewall rules, DNS)")
        print("    5. Exit")
        print()
        choice = input("  Select option [1-5]: ").strip()

        if choice == '1':
            auto = True
        elif choice == '2':
            restore_only = True
        elif choice == '3':
            purge_only = True
        elif choice == '4':
            _remove_downpour_firewall_rules()
            clean_hosts_file()
            reset_network()
            db.close()
            return
        else:
            print("  Exiting.")
            db.close()
            return

    restored = 0
    stats = {}

    if auto or restore_only:
        restored = restore_quarantined_files(db)

    if auto or purge_only:
        stats = purge_false_positive_db_entries(db)

    if auto:
        clean_hosts_file()
        reset_network()

    generate_report(stats, restored)

    db.close()


if __name__ == '__main__':
    main()
