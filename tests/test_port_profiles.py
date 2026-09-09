"""Unit tests for mega_threat_signatures port profiles (v29.42z, TASK-007).

Covers the context-aware PortProfile confidence/flagging logic introduced by
the concurrent agent (PortCategory/PortProfile + PORT_PROFILES registry).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mega_threat_signatures as mts


def test_known_rat_port_flags_without_context():
    """Metasploit's 4444 must flag high even with no process context."""
    p = mts.PORT_PROFILES[4444]
    assert p.category == mts.PortCategory.DEFINITELY_MALICIOUS
    assert p.calculate_confidence({}) >= 90
    assert p.should_flag({}, threshold=70) is True


def test_legitimate_process_drops_confidence():
    """Port 5000 lists 'upnp' as a legitimate use — confidence must drop."""
    p = mts.PORT_PROFILES[5000]
    ctx = {'process_name': 'upnp.exe'}
    assert p.calculate_confidence(ctx) < p.base_risk


def test_known_malware_process_raises_confidence_to_cap():
    p = mts.PORT_PROFILES[4444]
    ctx = {'process_name': 'meterpreter.exe'}
    assert p.calculate_confidence(ctx) == 100  # 98 * 1.5, capped at 100


def test_confidence_never_exceeds_bounds():
    """Confidence must stay within 0-100 for arbitrary contexts."""
    p = mts.PORT_PROFILES[4444]
    for ctx in ({}, {'process_name': 'metasploit.exe'},
                {'direction': 'inbound'}, {'process_name': 'x' * 500}):
        c = p.calculate_confidence(ctx)
        assert 0 <= c <= 100


def test_all_profiles_have_valid_shape():
    """Every profile must be internally consistent (port match, risk range)."""
    for port, prof in mts.PORT_PROFILES.items():
        assert prof.port == port, f"port key mismatch for {port}"
        assert 0 <= prof.base_risk <= 100
        assert isinstance(prof.known_malware, list)
        assert isinstance(prof.legitimate_uses, list)
        assert prof.name, f"missing name for port {port}"


def test_legitimate_service_ports_not_flagged():
    """Well-known legitimate services must never reach flag thresholds."""
    for port in (67, 123, 5353):  # DHCP/NTP/mDNS — LEGITIMATE_SERVICE class
        prof = mts.PORT_PROFILES.get(port)
        assert prof is not None, f"port {port} missing from PORT_PROFILES"
        assert prof.category == mts.PortCategory.LEGITIMATE_SERVICE
        assert prof.should_flag({'process_name': 'any'}) is False


def test_common_web_ports_are_low_risk():
    """80/443 must be LOW_RISK (never DEFINITELY_MALICIOUS) — FP guard."""
    for port in (80, 443):
        prof = mts.PORT_PROFILES.get(port)
        assert prof is not None
        assert prof.category == mts.PortCategory.LOW_RISK
        assert prof.base_risk <= 20
        assert prof.should_flag({'process_name': 'nginx'}) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])