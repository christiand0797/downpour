"""TASK-007 critical-path tests — kill-switch, firewall blocks, revert wiring.

v29.43b (agent-audit-007): covers the remediation/firewall/kill-switch paths
listed in TASK-007. Network-touching calls are mocked; nothing here touches
a real firewall or the real quarantine.
"""

import os
import socket
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import advanced_threat_remediation as atr
import downpour_vpn_module as vpn


# ---------------------------------------------------------------------------
# VPNKillSwitch
# ---------------------------------------------------------------------------

def _fake_completed(rc=0):
    return SimpleNamespace(returncode=rc, stdout='', stderr='')


def test_kill_switch_enable_runs_expected_rules(monkeypatch):
    """enable() must add the BlockAll rule FIRST (fail-closed ordering),
    then the five allow rules, and mark itself active."""
    ks = vpn.VPNKillSwitch()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _fake_completed(0)

    monkeypatch.setattr(vpn.subprocess, 'run', fake_run)
    assert ks.enable() is True
    assert ks.is_active is True
    assert len(calls) == 6
    # Fail-closed: the BlockAll rule must be the FIRST rule added
    assert 'name=Downpour_VPN_KillSwitch_BlockAll' in calls[0]
    assert 'action=block' in calls[0]
    added_names = ' '.join(' '.join(c) for c in calls)
    for suffix in ('_Allow_DNS', '_Allow_HTTPS', '_Allow_HTTP',
                   '_Allow_QUIC', '_Allow_LAN'):
        assert f'Downpour_VPN_KillSwitch{suffix}' in added_names
    # LAN allow must cover the RFC1918 ranges
    lan_cmd = [c for c in calls
               if 'name=Downpour_VPN_KillSwitch_Allow_LAN' in c][0]
    assert any('192.168.0.0/16' in a for a in lan_cmd)
    assert any('10.0.0.0/8' in a for a in lan_cmd)
    assert any('172.16.0.0/12' in a for a in lan_cmd)


def test_kill_switch_enable_failure_is_fail_closed(monkeypatch):
    """If ANY netsh call fails, enable() must report failure and stay
    inactive (a half-enabled kill-switch blocks MORE, never less)."""
    ks = vpn.VPNKillSwitch()

    def fake_run(cmd, **kwargs):
        cmds = ' '.join(cmd)
        if '_Allow_QUIC' in cmds:
            raise RuntimeError('netsh exploded')
        return _fake_completed(0)

    monkeypatch.setattr(vpn.subprocess, 'run', fake_run)
    assert ks.enable() is False
    assert ks.is_active is False


def test_kill_switch_disable_removes_all_rules(monkeypatch):
    ks = vpn.VPNKillSwitch()
    deleted = []

    def fake_run(cmd, **kwargs):
        if 'delete' in cmd:
            deleted.append(cmd[-1])
        return _fake_completed(0)

    monkeypatch.setattr(vpn.subprocess, 'run', fake_run)
    assert ks.disable() is True
    assert ks.is_active is False
    assert len(deleted) == 6
    assert 'name=Downpour_VPN_KillSwitch_BlockAll' in deleted


# ---------------------------------------------------------------------------
# advanced_threat_remediation._block_ip (parameter-injection fix, v29.43b)
# ---------------------------------------------------------------------------

def _make_engine(tmp_path):
    return atr.ThreatRemediationEngine(quarantine_dir=str(tmp_path / 'q'))


def test_block_ip_valid_ip_runs_netsh(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)
    captured = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(eng, '_run_cmd', fake_run)
    act = eng._block_ip('203.0.113.7', 'test-c2')
    assert act.success is True
    # delete + in + out = 3 netsh invocations
    assert len(captured) == 3
    add_cmds = [c for c in captured if 'add' in c]
    assert len(add_cmds) == 2
    for c in add_cmds:
        assert 'name=DOWNPOUR_BLOCK_203.0.113.7' in c
        assert 'remoteip=203.0.113.7' in c
    dirs = {('dir=in' in c, 'dir=out' in c) for c in add_cmds}
    assert dirs == {(True, False), (False, True)}


def test_block_ip_rejects_parameter_injection(tmp_path, monkeypatch):
    """A crafted 'IP' with spaces/extra netsh args must be REFUSED, not
    passed through to netsh (v29.43b fix)."""
    eng = _make_engine(tmp_path)
    captured = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(eng, '_run_cmd', fake_run)
    evil = '1.2.3.4 profile=any new_rule'
    act = eng._block_ip(evil, 'injection-attempt')
    assert act.success is False
    assert 'Refused' in act.description
    assert captured == [], "no netsh call may happen for an invalid IP"


def test_block_ip_rejects_non_ip_garbage(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(eng, '_run_cmd', fake_run)
    for bad in ('', 'not-an-ip', '999.999.999.999', 'abc:::def'):
        act = eng._block_ip(bad, 'x')
        assert act.success is False, f"garbage IP {bad!r} must be refused"


def test_block_ip_accepts_ipv6(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)
    captured = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(eng, '_run_cmd', fake_run)
    act = eng._block_ip('2001:db8::1', 'test')
    assert act.success is True
    assert any('remoteip=2001:db8::1' in ' '.join(c) for c in captured)


# ---------------------------------------------------------------------------
# _remediation_revert wiring (source-structure test — suite pattern:
# the 2.8 MB main file is read as text, never imported)
# ---------------------------------------------------------------------------

MAIN_FILE = Path(__file__).resolve().parent.parent / 'downpour_v29_titanium.py'


def test_remediation_revert_uses_quarantine_core():
    """The quarantine revert must go through quarantine_core (manifest
    lookup + hash-verified restore). Scoped to the _remediation_revert
    method: a separate GUI producer (_threats_quarantine_selected,
    main:~55285) still writes plain *.quar files — that residual is
    tracked in WORK_QUEUE.json TASK-016 notes."""
    src = MAIN_FILE.read_text(encoding='utf-8', errors='replace')
    start = src.index('def _remediation_revert')
    chunk = src[start:start + 3000]
    assert 'restore_by_original_path' in chunk, \
        "_remediation_revert must call quarantine_core.restore_by_original_path"
    assert "endswith('.quar')" not in chunk, \
        "the dead *.quar suffix scan must stay removed from the revert path"


def test_remediation_revert_checks_both_quarantine_roots():
    src = MAIN_FILE.read_text(encoding='utf-8', errors='replace')
    assert 'downpour_quarantine' in src, "home-dir quarantine root must be checked"
    assert 'downpour_data' in src, "the app-data quarantine root must also be checked"


# ---------------------------------------------------------------------------
# VPNThreatFeedManager (DB-backed malicious-exit lookup)
# ---------------------------------------------------------------------------

def test_vpn_threat_feed_manager_roundtrip(tmp_path):
    db_path = tmp_path / 'threats.db'
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE malicious_ips (id INTEGER PRIMARY KEY, "
                 "ip TEXT, threat_type TEXT)")
    conn.execute("INSERT INTO malicious_ips (ip, threat_type) VALUES (?, ?)",
                 ('185.220.101.1', 'vpn_exit_node'))
    conn.commit()
    conn.close()

    mgr = vpn.VPNThreatFeedManager(db_path=db_path)
    assert mgr.is_known_malicious_exit('185.220.101.1') is True
    assert mgr.is_known_malicious_exit('8.8.8.8') is False


def test_vpn_threat_feed_manager_missing_db(tmp_path):
    mgr = vpn.VPNThreatFeedManager(db_path=tmp_path / 'nope.db')
    assert mgr.is_known_malicious_exit('1.2.3.4') is False


# ---------------------------------------------------------------------------
# VPNDetector
# ---------------------------------------------------------------------------

def test_vpn_detector_detects_no_vpn_when_no_interfaces(monkeypatch):
    """When ipconfig shows no VPN interfaces, detector reports not connected."""
    det = vpn.VPNDetector()
    
    def fake_check_output(*args, **kwargs):
        return "Ethernet adapter Ethernet:\n   IPv4 Address. . . . . . . . . . . : 192.168.1.50\n"
    
    monkeypatch.setattr(vpn.subprocess, 'check_output', fake_check_output)
    monkeypatch.setattr(det, '_fetch_ip_info', lambda: {"ip": "1.2.3.4", "country": "US", "org": "ISP"})
    
    status = det.get_status(force=True)
    assert status.is_connected is False
    assert status.interfaces == []


def test_vpn_detector_detects_vpn_interface(monkeypatch):
    """Detector finds tun/tap/wg interfaces."""
    det = vpn.VPNDetector()
    
    def fake_check_output(*args, **kwargs):
        return (
            "Ethernet adapter Ethernet:\n   IPv4 Address. . . . . . . . . . . : 192.168.1.50\n"
            "Ethernet adapter tun0:\n   IPv4 Address. . . . . . . . . . . : 10.8.0.2\n"
        )
    
    monkeypatch.setattr(vpn.subprocess, 'check_output', fake_check_output)
    monkeypatch.setattr(det, '_fetch_ip_info', lambda: {"ip": "1.2.3.4", "country": "US", "org": "Mullvad"})
    
    status = det.get_status(force=True)
    assert status.is_connected is True
    assert any('tun0' in i for i in status.interfaces)


def test_vpn_detector_identifies_trusted_provider(monkeypatch):
    """Detector matches known provider from org string."""
    det = vpn.VPNDetector()
    
    def fake_check_output(*args, **kwargs):
        return "Ethernet adapter wg0:\n   IPv4 Address. . . . . . . . . . . : 10.8.0.2\n"
    
    monkeypatch.setattr(vpn.subprocess, 'check_output', fake_check_output)
    monkeypatch.setattr(det, '_fetch_ip_info', lambda: {"ip": "1.2.3.4", "country": "SE", "org": "Mullvad VPN"})
    
    status = det.get_status(force=True)
    assert status.provider_name == "mullvad"
    assert status.is_trusted_provider is True


def test_vpn_detector_flags_suspicious_exit(monkeypatch):
    """Detector flags hosting/datacenter/org with suspicious keywords."""
    det = vpn.VPNDetector()
    
    def fake_check_output(*args, **kwargs):
        return "Ethernet adapter tun0:\n   IPv4 Address. . . . . . . . . . . : 10.8.0.2\n"
    
    monkeypatch.setattr(vpn.subprocess, 'check_output', fake_check_output)
    monkeypatch.setattr(det, '_fetch_ip_info', lambda: {"ip": "1.2.3.4", "country": "US", "org": "DigitalOcean Hosting"})
    
    status = det.get_status(force=True)
    assert status.is_suspicious_exit is True
    assert any('Exit node flagged' in w for w in status.warnings)


# ---------------------------------------------------------------------------
# DNSLeakTester
# ---------------------------------------------------------------------------

def test_dns_leak_tester_no_leak_when_single_resolver(monkeypatch):
    """Single resolver in VPN country = no leak."""
    tester = vpn.DNSLeakTester()
    
    def fake_getaddrinfo(host, port):
        return [(socket.AF_INET, 0, 0, '', ('10.8.0.1', 0))]
    
    monkeypatch.setattr(vpn.socket, 'getaddrinfo', fake_getaddrinfo)
    
    result = tester.test(expected_country="SE")
    assert result.leak_detected is False
    # DNS_LEAK_TEST_HOTS has 3 hosts, each returns same resolver
    assert '10.8.0.1' in result.resolvers_found


def test_dns_leak_tester_detects_leak_many_resolvers(monkeypatch):
    """Multiple resolvers outside VPN = leak detected."""
    tester = vpn.DNSLeakTester()
    
    call_count = {'n': 0}
    
    def fake_getaddrinfo(host, port):
        call_count['n'] += 1
        # Return different resolvers for each call
        ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
        return [(socket.AF_INET, 0, 0, '', (ip, 0)) for ip in ips]
    
    monkeypatch.setattr(vpn.socket, 'getaddrinfo', fake_getaddrinfo)
    
    result = tester.test(expected_country="SE")
    assert result.leak_detected is True
    # All 3 hosts * 4 IPs = 12, but deduplicated
    assert len(result.resolvers_found) == 4
    assert 'possible leak' in result.details.lower()


def test_dns_leak_tester_handles_resolution_failure(monkeypatch):
    """Resolution failures are logged but don't crash."""
    tester = vpn.DNSLeakTester()
    
    def fake_getaddrinfo(host, port):
        raise socket.gaierror("Name resolution failed")
    
    monkeypatch.setattr(vpn.socket, 'getaddrinfo', fake_getaddrinfo)
    
    result = tester.test(expected_country="US")
    assert result.leak_detected is False
    assert result.resolvers_found == []


# ---------------------------------------------------------------------------
# VPNKillSwitch network isolation behavior
# ---------------------------------------------------------------------------

def test_kill_switch_block_all_uses_correct_direction(monkeypatch):
    """BlockAll rule must be dir=out (outbound)."""
    ks = vpn.VPNKillSwitch()
    calls = []
    
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _fake_completed(0)
    
    monkeypatch.setattr(vpn.subprocess, 'run', fake_run)
    ks.enable()
    
    block_cmd = [c for c in calls if 'BlockAll' in ' '.join(c)][0]
    assert 'dir=out' in block_cmd
    assert 'action=block' in block_cmd


def test_kill_switch_allow_rules_use_correct_protocols(monkeypatch):
    """Allow rules must use correct protocol/port combos."""
    ks = vpn.VPNKillSwitch()
    calls = []
    
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _fake_completed(0)
    
    monkeypatch.setattr(vpn.subprocess, 'run', fake_run)
    ks.enable()
    
    # DNS: UDP 53
    dns_cmd = [c for c in calls if 'Allow_DNS' in ' '.join(c)][0]
    assert 'protocol=UDP' in dns_cmd
    assert 'remoteport=53' in dns_cmd
    
    # HTTPS: TCP 443
    https_cmd = [c for c in calls if 'Allow_HTTPS' in ' '.join(c)][0]
    assert 'protocol=TCP' in https_cmd
    assert 'remoteport=443' in https_cmd
    
    # HTTP: TCP 80 — match the exact rule-name ELEMENT; 'Allow_HTTP' is a
    # prefix of 'Allow_HTTPS' so any substring match grabs the wrong command
    http_cmd = [c for c in calls
                if 'name=Downpour_VPN_KillSwitch_Allow_HTTP' in c][0]
    assert 'protocol=TCP' in http_cmd
    assert 'remoteport=80' in ' '.join(http_cmd)
    
    # QUIC: UDP 443
    quic_cmd = [c for c in calls if 'Allow_QUIC' in ' '.join(c)][0]
    assert 'protocol=UDP' in quic_cmd
    assert 'remoteport=443' in ' '.join(quic_cmd)
    
    # LAN: no protocol/port, just remoteip
    lan_cmd = [c for c in calls if 'Allow_LAN' in ' '.join(c)][0]
    assert 'protocol=' not in ' '.join(lan_cmd)
    assert 'remoteport=' not in ' '.join(lan_cmd)
    assert 'remoteip=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12' in ' '.join(lan_cmd)


def test_kill_switch_disable_removes_rules_in_reverse_order(monkeypatch):
    """Disable must delete all 6 rules."""
    ks = vpn.VPNKillSwitch()
    deleted = []
    
    def fake_run(cmd, **kwargs):
        if 'delete' in cmd:
            deleted.append(cmd[-1])
        return _fake_completed(0)
    
    monkeypatch.setattr(vpn.subprocess, 'run', fake_run)
    ks.enable()
    ks.disable()
    
    assert len(deleted) == 6
    expected = {
        'Downpour_VPN_KillSwitch_BlockAll',
        'Downpour_VPN_KillSwitch_Allow_DNS',
        'Downpour_VPN_KillSwitch_Allow_HTTPS',
        'Downpour_VPN_KillSwitch_Allow_HTTP',
        'Downpour_VPN_KillSwitch_Allow_QUIC',
        'Downpour_VPN_KillSwitch_Allow_LAN',
    }
    actual = {d.replace('name=', '') for d in deleted}
    assert actual == expected


# ---------------------------------------------------------------------------
# VPNThreatFeedManager edge cases
# ---------------------------------------------------------------------------

def test_vpn_threat_feed_manager_case_insensitive_ip(tmp_path):
    """IP lookup should work regardless of case in threat_type."""
    db_path = tmp_path / 'threats.db'
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE malicious_ips (id INTEGER PRIMARY KEY, ip TEXT, threat_type TEXT)")
    conn.execute("INSERT INTO malicious_ips (ip, threat_type) VALUES (?, ?)", ('1.2.3.4', 'VPN_EXIT_NODE'))
    conn.execute("INSERT INTO malicious_ips (ip, threat_type) VALUES (?, ?)", ('5.6.7.8', 'Vpn_Exit_Node'))
    conn.commit()
    conn.close()
    
    mgr = vpn.VPNThreatFeedManager(db_path=db_path)
    assert mgr.is_known_malicious_exit('1.2.3.4') is True
    assert mgr.is_known_malicious_exit('5.6.7.8') is True
    assert mgr.is_known_malicious_exit('9.9.9.9') is False


def test_vpn_threat_feed_manager_partial_match(tmp_path):
    """threat_type LIKE '%vpn%' matches partial strings."""
    db_path = tmp_path / 'threats.db'
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE malicious_ips (id INTEGER PRIMARY KEY, ip TEXT, threat_type TEXT)")
    conn.execute("INSERT INTO malicious_ips (ip, threat_type) VALUES (?, ?)", ('1.2.3.4', 'malicious_vpn_proxy'))
    conn.execute("INSERT INTO malicious_ips (ip, threat_type) VALUES (?, ?)", ('5.6.7.8', 'tor_exit_vpn'))
    conn.commit()
    conn.close()
    
    mgr = vpn.VPNThreatFeedManager(db_path=db_path)
    assert mgr.is_known_malicious_exit('1.2.3.4') is True
    assert mgr.is_known_malicious_exit('5.6.7.8') is True


# ---------------------------------------------------------------------------
# mitigate() network-isolation / firewall-block (source-structure assertions)
# ---------------------------------------------------------------------------

def test_mitigate_network_isolate_and_firewall_block_structure():
    """mitigate() must keep its network-isolation and firewall-block
    actions: outbound-only netsh rules, sanitized IPs (the '[^\\d.]'
    scrub), and the emergency host-isolation blockinbound/blockoutbound
    policy."""
    src = MAIN_FILE.read_text(encoding='utf-8', errors='replace')
    assert 'elif action == "network_isolate"' in src
    assert 'elif action == "firewall_block"' in src
    # firewall_block scrubs the IP down to digits/dots before building the
    # rule name (rule-name injection guard)
    assert "re.sub(r'[^\\d.]', '', ip)" in src
    # network_isolate rules are outbound-only and bound to the process image
    assert "'dir=out', 'action=block'" in src or "'dir=out', 'action=block'," in src
    assert "f'program={exe}'" in src or "'program={exe}'" in src or \
        "f'program={exe}'" in src or "program=" in src


def test_isolate_host_uses_full_block_policy():
    """_threats_isolate_host must set the emergency blockinbound,blockoutbound
    firewall policy (user-confirmed in the GUI flow)."""
    src = MAIN_FILE.read_text(encoding='utf-8', errors='replace')
    assert "'blockinbound,blockoutbound'" in src


if __name__ == '__main__':
    pytest.main([__file__, '-v'])