"""Unit tests for ConfigManager - thread-safe configuration with hot-reload."""

import os
import sys
import tempfile
import time
import threading
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ConfigManager, CONFIG


class TestConfigManager:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self.tmpdir) / 'test_config.json'
        self.sig_path = Path(str(self.config_path) + '.sig')

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_initial_config_loaded_from_dict(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'TEST': {'key': 'value'}})
        assert cm.get('TEST', 'key') == 'value'
        cm.stop_watching()

    def test_get_returns_fallback_for_missing(self):
        cm = ConfigManager(config_path=str(self.config_path))
        assert cm.get('MISSING', 'key', 'fallback') == 'fallback'
        cm.stop_watching()

    def test_get_section_returns_copy(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'SEC': {'a': 1}})
        sec = cm.get_section('SEC')
        sec['a'] = 999
        assert cm.get('SEC', 'a') == 1  # original unchanged
        cm.stop_watching()

    def test_set_persists_to_file(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={})
        assert cm.set('NEW', 'key', 'value') is True
        # reload and verify
        cm2 = ConfigManager(config_path=str(self.config_path))
        assert cm2.get('NEW', 'key') == 'value'
        cm.stop_watching()
        cm2.stop_watching()

    def test_update_merges_multiple_values(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={})
        assert cm.update({'A': {'x': 1}, 'B': {'y': 2}}) is True
        assert cm.get('A', 'x') == 1
        assert cm.get('B', 'y') == 2
        cm.stop_watching()

    def test_save_and_get_all(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'S': {'k': 'v'}})
        all_cfg = cm.get_all()
        assert all_cfg == {'S': {'k': 'v'}}
        cm.stop_watching()

    def test_configparser_compat_interface(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'SEC': {'int': '42', 'bool': 'true'}})
        assert cm.has_section('SEC')
        assert cm.has_option('SEC', 'int')
        assert cm.getint('SEC', 'int') == 42
        assert cm.getfloat('SEC', 'float', 3.14) == 3.14
        assert cm.getboolean('SEC', 'bool') is True
        assert list(cm.sections()) == ['SEC']
        cm.stop_watching()

    def test_dict_like_access(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'X': {'y': 'z'}})
        assert 'X' in cm
        assert cm['X']['y'] == 'z'
        assert list(cm.keys()) == ['X']
        cm.stop_watching()

    def test_thread_safety_concurrent_reads(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'DATA': {'val': 0}})
        results = []

        def reader():
            for _ in range(100):
                results.append(cm.get('DATA', 'val'))

        threads = [threading.Thread(target=reader) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert all(r == 0 for r in results)
        cm.stop_watching()

    def test_thread_safety_concurrent_writes(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={})
        errors = []

        def writer(i):
            try:
                for j in range(50):
                    cm.set('SEC', f'key{i}_{j}', j)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors
        cm.stop_watching()

    def test_hot_reload_on_file_change(self):
        # Write initial config
        self.config_path.write_text(json.dumps({'LIVE': {'val': 'old'}}))
        cm = ConfigManager(config_path=str(self.config_path))
        assert cm.get('LIVE', 'val') == 'old'

        # Modify file — v29.42w (TASK-014): external edits must carry a valid
        # signature to be applied (an unsigned edit after a signature exists
        # is treated as tamper and rejected). Simulate an authorized external
        # change by writing the config AND its signature.
        time.sleep(0.15)  # debounce
        new_cfg = {'LIVE': {'val': 'new'}}
        self.config_path.write_text(json.dumps(new_cfg, indent=2), encoding='utf-8')
        self.sig_path.write_text(cm._compute_sig(new_cfg), encoding='utf-8')
        deadline = time.time() + 3.0
        while time.time() < deadline and cm.get('LIVE', 'val') != 'new':
            time.sleep(0.05)  # allow watcher to pick up

        assert cm.get('LIVE', 'val') == 'new', f"Expected 'new', got {cm.get('LIVE', 'val')}"
        cm.stop_watching()

    def test_callback_registered_on_change(self):
        self.config_path.write_text(json.dumps({'CB': {'v': '1'}}))
        cm = ConfigManager(config_path=str(self.config_path))
        seen = []

        def cb(cfg):
            seen.append(cfg.get('CB', {}).get('v'))

        cm.register_callback(cb)
        time.sleep(0.15)
        # Authorized external change: config + valid signature (v29.42w).
        new_cfg = {'CB': {'v': '2'}}
        self.config_path.write_text(json.dumps(new_cfg, indent=2), encoding='utf-8')
        self.sig_path.write_text(cm._compute_sig(new_cfg), encoding='utf-8')
        deadline = time.time() + 3.0
        while time.time() < deadline and '2' not in seen:
            time.sleep(0.05)

        assert '2' in seen
        cm.stop_watching()

    def test_tamper_detection_rejects_unsigned_edit(self):
        # v29.42w (TASK-014): after a signature exists, an out-of-band edit
        # that does not update the signature must be REJECTED (config kept)
        # and must raise the tamper flag + callbacks.
        cm = ConfigManager(config_path=str(self.config_path),
                           initial_config={'SEC': {'a': 1}})
        assert cm.set('SEC', 'a', 2) is True  # signed on save
        tampered = []
        cm.register_tamper_callback(lambda msg: tampered.append(msg))

        time.sleep(1.2)  # outlast ConfigChangeHandler's 1.0s debounce window
        self.config_path.write_text(json.dumps({'SEC': {'a': 999}}), encoding='utf-8')

        deadline = time.time() + 3.0
        while time.time() < deadline and not cm.tamper_detected:
            time.sleep(0.05)

        assert cm.tamper_detected is True
        assert tampered, "tamper callback not invoked"
        assert cm.get('SEC', 'a') == 2, "tampered config must be rejected"
        cm.stop_watching()

    def test_callback_unregister(self):
        cm = ConfigManager(config_path=str(self.config_path), initial_config={})
        seen = []

        def cb(cfg):
            seen.append(cfg)

        cm.register_callback(cb)
        cm.unregister_callback(cb)
        cm.set('A', 'b', 'c')
        assert not seen
        cm.stop_watching()

    def test_stop_watching_idempotent(self):
        cm = ConfigManager(config_path=str(self.config_path))
        cm.stop_watching()
        cm.stop_watching()  # should not raise
        assert not cm.is_watching()

    def test_invalid_json_falls_back_to_initial(self):
        self.config_path.write_text('not valid json {')
        cm = ConfigManager(config_path=str(self.config_path), initial_config={'FB': {'k': 'v'}})
        assert cm.get('FB', 'k') == 'v'
        cm.stop_watching()

    def test_is_watching_reflects_state(self):
        cm = ConfigManager(config_path=str(self.config_path))
        assert cm.is_watching() is True
        cm.stop_watching()
        assert cm.is_watching() is False


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])