"""Unit tests for EmergencyResponse - snapshot, process killer, logging."""

import os
import sys
import tempfile
import json
import shutil
from pathlib import Path
from unittest import mock
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import emergency_response as er_module
from emergency_response import EmergencyResponse, check_cve_threat_priority


class TestEmergencyResponse:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmpdir)

    def teardown_method(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_initialization_creates_dirs(self):
        er = EmergencyResponse()
        assert Path("emergency_snapshots").exists()
        assert Path("emergency_quarantine").exists()
        assert er.response_log == []

    def test_check_cve_threat_priority_without_kev(self):
        # Mock _KEV_AVAILABLE to False
        with mock.patch.object(er_module, '_KEV_AVAILABLE', False):
            result = check_cve_threat_priority('CVE-2024-1234')
            assert result['priority'] == 'UNKNOWN'
            assert 'KEV data unavailable' in result['recommendation']

    def test_check_cve_threat_priority_with_kev_not_found(self):
        mock_scanner = mock.MagicMock()
        mock_scanner.get_kev_catalog.return_value = [
            {'cveID': 'CVE-2023-1111', 'description': 'other'}
        ]
        with mock.patch.object(er_module, '_KEV_AVAILABLE', True):
            with mock.patch.object(er_module, 'VulnerabilityScanner', return_value=mock_scanner):
                result = check_cve_threat_priority('CVE-2024-1234')
                assert result['priority'] == 'HIGH'
                assert result['in_kev'] is False

    def test_check_cve_threat_priority_with_kev_found(self):
        mock_scanner = mock.MagicMock()
        mock_scanner.get_kev_catalog.return_value = [
            {'cveID': 'CVE-2024-1234', 'description': 'exploited', 'dueDate': '2024-01-01'}
        ]
        with mock.patch.object(er_module, '_KEV_AVAILABLE', True):
            with mock.patch.object(er_module, 'VulnerabilityScanner', return_value=mock_scanner):
                result = check_cve_threat_priority('CVE-2024-1234')
                assert result['priority'] == 'CRITICAL'
                assert result['in_kev'] is True
                assert 'IMMEDIATE patch required' in result['recommendation']

    def test_take_system_snapshot_returns_path(self):
        er = EmergencyResponse()
        with mock.patch('psutil.process_iter') as mock_proc_iter:
            mock_proc_iter.return_value = []
            with mock.patch('psutil.net_connections') as mock_net_conns:
                mock_net_conns.return_value = []
                path = er.take_system_snapshot('test123')
                assert path.endswith('emergency_snapshot_test123.json')
                assert os.path.exists(path)
                with open(path) as f:
                    data = json.load(f)
                    assert data['response_id'] == 'test123'
                    assert 'processes' in data
                    assert 'network_connections' in data

    def test_take_system_snapshot_captures_processes(self):
        er = EmergencyResponse()
        mock_proc = mock.MagicMock()
        mock_proc.info = {
            'pid': 1234,
            'name': 'test.exe',
            'exe': 'C:\\test.exe',
            'cmdline': ['test.exe', 'arg1'],
            'username': 'user',
            'create_time': 1234567890
        }
        with mock.patch('psutil.process_iter', return_value=[mock_proc]):
            with mock.patch('psutil.net_connections', return_value=[]):
                path = er.take_system_snapshot('test123')
                with open(path) as f:
                    data = json.load(f)
                    assert len(data['processes']) == 1
                    assert data['processes'][0]['pid'] == 1234

    def test_take_system_snapshot_captures_network(self):
        er = EmergencyResponse()
        mock_conn = mock.MagicMock()
        mock_conn.laddr = mock.MagicMock(ip='192.168.1.1', port=1234)
        mock_conn.raddr = mock.MagicMock(ip='8.8.8.8', port=53)
        mock_conn.status = 'ESTABLISHED'
        mock_conn.pid = 5678
        with mock.patch('psutil.process_iter', return_value=[]):
            with mock.patch('psutil.net_connections', return_value=[mock_conn]):
                path = er.take_system_snapshot('test123')
                with open(path) as f:
                    data = json.load(f)
                    assert len(data['network_connections']) == 1
                    assert data['network_connections'][0]['remote_address'] == '8.8.8.8:53'

    def test_kill_suspicious_processes_detects_by_name(self):
        er = EmergencyResponse()
        mock_proc = mock.MagicMock()
        mock_proc.info = {'pid': 999, 'name': 'mimikatz.exe', 'exe': 'C:\\mimikatz.exe'}
        with mock.patch('psutil.process_iter', return_value=[mock_proc]):
            killed = er.kill_suspicious_processes()
            assert len(killed) == 1
            assert killed[0]['pid'] == 999
            assert 'Suspicious name' in killed[0]['reason']
            mock_proc.kill.assert_called_once()

    def test_kill_suspicious_processes_detects_by_path(self):
        er = EmergencyResponse()
        mock_proc = mock.MagicMock()
        mock_proc.info = {'pid': 888, 'name': 'normal.exe', 'exe': 'C:\\users\\public\\evil.exe'}
        with mock.patch('psutil.process_iter', return_value=[mock_proc]):
            killed = er.kill_suspicious_processes()
            assert len(killed) == 1
            assert 'Suspicious location' in killed[0]['reason']

    def test_kill_suspicious_processes_ignores_legit(self):
        er = EmergencyResponse()
        mock_proc = mock.MagicMock()
        mock_proc.info = {'pid': 777, 'name': 'notepad.exe', 'exe': 'C:\\Windows\\notepad.exe'}
        with mock.patch('psutil.process_iter', return_value=[mock_proc]):
            killed = er.kill_suspicious_processes()
            assert len(killed) == 0

    def test_kill_suspicious_processes_handles_access_denied(self):
        er = EmergencyResponse()
        mock_proc = mock.MagicMock()
        mock_proc.info = {'pid': 666, 'name': 'mimikatz.exe', 'exe': 'C:\\mimikatz.exe'}
        import psutil
        mock_proc.kill.side_effect = psutil.AccessDenied
        with mock.patch('psutil.process_iter', return_value=[mock_proc]):
            killed = er.kill_suspicious_processes()
            assert len(killed) == 0  # AccessDenied should be caught

    def test_emergency_backup_creates_dir(self):
        er = EmergencyResponse()
        with mock.patch('os.path.expanduser', return_value='/home/user'):
            with mock.patch('os.path.exists', return_value=False):
                path = er.emergency_backup('test123')
                assert path != ""  # Directory created even if empty
                assert 'emergency_backup_test123' in path

    def test_log_emergency_response_creates_log(self):
        er = EmergencyResponse()
        er.log_emergency_response('resp123', ['step1'], ['step2'])
        assert os.path.exists(er.response_log_path)
        with open(er.response_log_path) as f:
            log = json.load(f)
            assert len(log) == 1
            assert log[0]['response_id'] == 'resp123'
            assert log[0]['steps_completed'] == ['step1']
            assert log[0]['steps_failed'] == ['step2']

    def test_log_emergency_response_appends_to_existing(self):
        er = EmergencyResponse()
        er.log_emergency_response('resp1', ['a'], [])
        er.log_emergency_response('resp2', ['b'], [])
        with open(er.response_log_path) as f:
            log = json.load(f)
            assert len(log) == 2

    def test_log_emergency_response_handles_corrupted_json(self):
        er = EmergencyResponse()
        with open(er.response_log_path, 'w') as f:
            f.write('not valid json')
        er.log_emergency_response('resp1', ['a'], [])
        with open(er.response_log_path) as f:
            log = json.load(f)
            assert len(log) == 1
            assert log[0]['response_id'] == 'resp1'

    def test_log_emergency_response_handles_non_list(self):
        er = EmergencyResponse()
        with open(er.response_log_path, 'w') as f:
            json.dump({'not': 'a list'}, f)
        er.log_emergency_response('resp1', ['a'], [])
        with open(er.response_log_path) as f:
            log = json.load(f)
            assert len(log) == 1


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])