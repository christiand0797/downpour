"""
Downpour Auto-Updater Module
Checks GitHub for updates, downloads and applies them automatically.
"""
from __future__ import annotations
import os
import sys
import json
import time
import shutil
import subprocess
import threading
import logging
import zipfile
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timedelta

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# GitHub repository info
GITHUB_REPO = "christiand0797/downpour"
GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
CURRENT_VERSION = "29.124"

# Files to update (relative to repo root)
UPDATE_FILES = [
    "downpour_v29_titanium.py",
    "cognitive_immune_system.py",
    "revolutionary_enhancements.py",
    "enhanced_memory_manager.py",
    "security_hardening.py",
    "defender_compatibility.py",
    "downpour_cleanup_module.py",
    "downpour_remote_access.py",
    "downpour_vpn_module.py",
    "downpour_updater.py",
    "sensor_hub.py",
    "threat_feed_aggregator.py",
    "vulnerability_scanner.py",
    "pe_analyzer.py",
    "advanced_defense_suite.py",
    "intel_cache.py",
    "quarantine_core.py",
    "trust_check.py",
    "enhanced_logging.py",
    "downpour_bypass_system.py",
    "enhanced_bypass_system.py",
    "adaptive_security_bypass.py",
    "defender_bypass_system.py",
    "process_mitigation.py",
    "native_probes.py",
    "security_audit.py",
    "system_cleanup.py",
    "threat_hunt_engine.py",
    "forensic_report.py",
    "emergency_response.py",
    "backup_verifier.py",
    "ad_attack_detector.py",
    "amsi_bypass_detector.py",
    "anti_forensics_detector.py",
    "behavior_scanner.py",
    "beacon_detector.py",
    "bluetooth_security_monitor.py",
    "boot_integrity_monitor.py",
    "browser_security_monitor.py",
    "child_process_guard.py",
    "code_integrity.py",
    "credential_guard_monitor.py",
    "data_exfiltration_monitor.py",
    "dll_hijack_detector.py",
    "dns_cache_watch.py",
    "kimwolf_botnet_detector.py",
    "lolbins_detector.py",
    "misp_feed.py",
    "opencti_client.py",
    "ransomware_early_warning.py",
    "sandbox_analyzer.py",
    "stix_taxii_feed.py",
    "dark_web_intel.py",
    "advanced_file_analyzer.py",
    "advanced_threat_remediation.py",
    "advanced_device_profiler.py",
    "ai_security_engine.py",
    "requirements.txt",
    "INSTALL_DOWNPOUR.bat",
    "LAUNCH_DOWNPOUR.bat",
]

# Directories to create
UPDATE_DIRS = [
    "downpour_data",
    "downpour_data/logs",
    "downpour_data/config",
    "downpour_data/intel",
    "downpour_data/models",
    "downpour_data/quarantine",
    "downpour_data/quarantine/files",
    "downpour_data/quarantine/metadata",
    "downpour_data/quarantine/snapshots",
    "downpour_data/sandbox",
    "downpour_data/containment",
    "downpour_data/backups",
    "downpour_data/cache",
    "downpour_data/exports",
    "downpour_data/docs",
    "downpour_data/reports",
    "downpour_tmp",
    "_temp_scripts",
]

logger = logging.getLogger("Downpour.Updater")


class DownpourUpdater:
    """Handles automatic updates from GitHub."""

    def __init__(self, app_dir: str, callback: Optional[Callable] = None):
        self.app_dir = Path(app_dir).resolve()
        self.callback = callback
        self.current_version = CURRENT_VERSION
        self.latest_version: Optional[str] = None
        self.release_info: Optional[Dict] = None
        self._stop_event = threading.Event()

    def _notify(self, status: str, progress: float = 0.0, message: str = ""):
        """Send status update to callback."""
        if self.callback:
            try:
                self.callback(status, progress, message)
            except Exception:
                pass
        logger.info(f"Updater: {status} - {message}")

    def check_for_updates(self, force: bool = False) -> Dict[str, Any]:
        """Check GitHub for latest release."""
        if not REQUESTS_AVAILABLE:
            return {"available": False, "error": "requests not installed"}

        self._notify("checking", 0.1, "Checking for updates...")

        try:
            # Get latest release
            url = f"{GITHUB_API}/repos/{GITHUB_REPO}/releases/latest"
            headers = {"Accept": "application/vnd.github.v3+json"}
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            release = resp.json()

            self.latest_version = release.get("tag_name", "").lstrip("v")
            self.release_info = release

            # Compare versions
            current = self._parse_version(self.current_version)
            latest = self._parse_version(self.latest_version)

            update_available = latest > current

            result = {
                "available": update_available,
                "current": self.current_version,
                "latest": self.latest_version,
                "release_notes": release.get("body", ""),
                "published_at": release.get("published_at", ""),
                "download_url": release.get("zipball_url", ""),
            }

            if update_available:
                self._notify("update_available", 0.5, f"Update available: v{self.latest_version}")
            else:
                self._notify("up_to_date", 1.0, "Already on latest version")

            return result

        except Exception as e:
            logger.error(f"Update check failed: {e}")
            self._notify("error", 0, f"Update check failed: {e}")
            return {"available": False, "error": str(e)}

    def _parse_version(self, version: str) -> tuple:
        """Parse version string to comparable tuple."""
        parts = []
        for part in version.replace("-", ".").split("."):
            try:
                parts.append(int(part))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    def download_and_install(self, progress_callback: Optional[Callable] = None) -> bool:
        """Download and apply update from GitHub."""
        if not self.latest_version:
            if not self.check_for_updates()["available"]:
                return False

        self._notify("downloading", 0.1, "Downloading update...")

        try:
            # Download zipball
            zip_url = self.release_info.get("zipball_url")
            if not zip_url:
                zip_url = f"{GITHUB_API}/repos/{GITHUB_REPO}/zipball/v{self.latest_version}"

            resp = requests.get(zip_url, stream=True, timeout=60)
            resp.raise_for_status()

            total_size = int(resp.headers.get("content-length", 0))
            downloaded = 0

            # Save to temp file
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                zip_path = tmp.name
                for chunk in resp.iter_content(chunk_size=8192):
                    if self._stop_event.is_set():
                        return False
                    if chunk:
                        tmp.write(chunk)
                        downloaded += len(chunk)
                        if total_size and progress_callback:
                            progress = 0.1 + (downloaded / total_size) * 0.6
                            progress_callback(progress, f"Downloaded {downloaded}/{total_size} bytes")

            self._notify("extracting", 0.7, "Extracting update...")

            # Extract to temp directory
            with tempfile.TemporaryDirectory() as extract_dir:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(extract_dir)

                # Find extracted repo folder (github creates folder like user-repo-hash)
                extracted_folders = [d for d in Path(extract_dir).iterdir() if d.is_dir()]
                if not extracted_folders:
                    raise Exception("No extracted folder found")
                repo_dir = extracted_folders[0]

                # Backup current files
                self._notify("backing_up", 0.75, "Backing up current installation...")
                backup_dir = self.app_dir / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                backup_dir.mkdir(parents=True, exist_ok=True)

                for f in UPDATE_FILES:
                    src = self.app_dir / f
                    if src.exists():
                        dst = backup_dir / f
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dst)

                # Copy new files
                self._notify("installing", 0.8, "Installing update...")
                for f in UPDATE_FILES:
                    src = repo_dir / f
                    if src.exists():
                        dst = self.app_dir / f
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dst)

                # Create directories
                for d in UPDATE_DIRS:
                    (self.app_dir / d).mkdir(parents=True, exist_ok=True)

                # Update version file
                version_file = self.app_dir / "VERSION"
                version_file.write_text(f"{self.latest_version}\n{datetime.now().isoformat()}")

                # Update requirements
                self._notify("updating_deps", 0.9, "Updating dependencies...")
                self._update_dependencies()

            # Cleanup
            try:
                os.unlink(zip_path)
            except Exception:
                pass

            self._notify("complete", 1.0, f"Updated to v{self.latest_version}")
            return True

        except Exception as e:
            logger.error(f"Update failed: {e}")
            self._notify("error", 0, f"Update failed: {e}")
            return False

    def _update_dependencies(self):
        """Update Python dependencies."""
        try:
            venv_python = self.app_dir / ".venv" / "Scripts" / "python.exe"
            if venv_python.exists():
                subprocess.run([
                    str(venv_python), "-m", "pip", "install", "-r",
                    str(self.app_dir / "requirements.txt"),
                    "--quiet", "--disable-pip-version-check"
                ], timeout=300, capture_output=True)
        except Exception as e:
            logger.warning(f"Dependency update failed: {e}")

    def cancel(self):
        """Cancel ongoing update."""
        self._stop_event.set()

    def get_changelog(self) -> str:
        """Get changelog from latest release."""
        if self.release_info:
            return self.release_info.get("body", "No changelog available")
        return "No release info available"


class UpdaterUI:
    """GUI integration for updater."""

    def __init__(self, app, updater: DownpourUpdater):
        self.app = app
        self.updater = updater
        self.update_window = None

    def add_update_button(self, parent_frame):
        """Add update button to a frame."""
        try:
            import tkinter as tk
            from tkinter import ttk

            btn_frame = ttk.Frame(parent_frame)
            btn_frame.pack(side="right", padx=5)

            self.update_btn = ttk.Button(
                btn_frame,
                text="\U0001f504 Check Updates",
                command=self._on_check_updates,
                style="Accent.TButton"
            )
            self.update_btn.pack(side="right", padx=2)

            # Version label
            self.version_lbl = ttk.Label(
                btn_frame,
                text=f"v{CURRENT_VERSION}",
                font=("Consolas", 8),
                foreground="#6688aa"
            )
            self.version_lbl.pack(side="right", padx=10)

            # Auto-check on startup
            self.app.after(5000, self._auto_check)

        except Exception as e:
            logger.error(f"Failed to add update button: {e}")

    def _auto_check(self):
        """Auto-check for updates on startup."""
        def check():
            result = self.updater.check_for_updates()
            if result.get("available"):
                self._show_update_notification(result)

        threading.Thread(target=check, daemon=True).start()

    def _on_check_updates(self):
        """Manual update check."""
        self.update_btn.config(state="disabled", text="\U0001f504 Checking...")
        self._notify("Checking for updates...")

        def check():
            result = self.updater.check_for_updates()
            self.app.after(0, lambda: self._on_check_complete(result))

        threading.Thread(target=check, daemon=True).start()

    def _on_check_complete(self, result):
        """Handle update check result."""
        self.update_btn.config(state="normal", text="\U0001f504 Check Updates")

        if result.get("available"):
            self._show_update_dialog(result)
        elif result.get("error"):
            self._notify(f"Update check failed: {result['error']}")
        else:
            self._notify("Already on latest version")

    def _show_update_dialog(self, result):
        """Show update available dialog."""
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox

            dialog = tk.Toplevel(self.app)
            dialog.title("Update Available")
            dialog.geometry("500x400")
            dialog.resizable(False, False)
            dialog.transient(self.app)
            dialog.grab_set()

            # Center
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - 250
            y = (dialog.winfo_screenheight() // 2) - 200
            dialog.geometry(f"+{x}+{y}")

            ttk.Label(dialog, text=f"Downpour v{result['latest']} Available",
                     font=("Consolas", 14, "bold")).pack(pady=15)

            ttk.Label(dialog, text=f"Current: v{result['current']}",
                     font=("Consolas", 10)).pack()

            # Changelog
            changelog_frame = ttk.Frame(dialog)
            changelog_frame.pack(fill="both", expand=True, padx=15, pady=10)

            changelog_text = tk.Text(changelog_frame, height=12, wrap="word",
                                    font=("Consolas", 9), bg="#1a1a2e", fg="#00ffcc")
            changelog_text.pack(fill="both", expand=True)
            changelog_text.insert("1.0", result.get("release_notes", "No changelog"))
            changelog_text.config(state="disabled")

            # Buttons
            btn_frame = ttk.Frame(dialog)
            btn_frame.pack(pady=15)

            def do_update():
                dialog.destroy()
                self._start_update()

            ttk.Button(btn_frame, text="Update Now", command=do_update,
                      style="Accent.TButton").pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Later", command=dialog.destroy).pack(side="left", padx=5)

        except Exception as e:
            logger.error(f"Update dialog error: {e}")

    def _show_update_notification(self, result):
        """Show toast notification."""
        try:
            import tkinter as tk
            from tkinter import messagebox

            if messagebox.askyesno("Update Available",
                f"Downpour v{result['latest']} is available!\n\n"
                f"Current: v{result['current']}\n\n"
                f"Update now?"):
                self._start_update()
        except Exception:
            pass

    def _start_update(self):
        """Start update process."""
        try:
            import tkinter as tk
            from tkinter import ttk

            # Progress window
            prog_win = tk.Toplevel(self.app)
            prog_win.title("Updating Downpour")
            prog_win.geometry("400x150")
            prog_win.resizable(False, False)
            prog_win.transient(self.app)
            prog_win.grab_set()

            ttk.Label(prog_win, text="Updating Downpour...",
                     font=("Consolas", 12)).pack(pady=15)

            prog_var = tk.DoubleVar()
            prog_bar = ttk.Progressbar(prog_win, variable=prog_var, maximum=100)
            prog_bar.pack(fill="x", padx=20, pady=10)

            status_lbl = ttk.Label(prog_win, text="Starting...", font=("Consolas", 9))
            status_lbl.pack(pady=5)

            def progress_cb(progress: float, msg: str):
                self.app.after(0, lambda: [
                    prog_var.set(progress * 100),
                    status_lbl.config(text=msg)
                ])

            def do_update():
                success = self.updater.download_and_install(progress_cb)
                self.app.after(0, lambda: self._update_done(prog_win, success))

            threading.Thread(target=do_update, daemon=True).start()

        except Exception as e:
            logger.error(f"Update start failed: {e}")

    def _update_done(self, window, success: bool):
        """Handle update completion."""
        window.destroy()
        if success:
            import tkinter.messagebox as mb
            mb.showinfo("Update Complete",
                f"Downpour updated to v{self.updater.latest_version}\n\n"
                "Please restart the application.")
            self.version_lbl.config(text=f"v{self.updater.latest_version}")
        else:
            import tkinter.messagebox as mb
            mb.showerror("Update Failed", "Update failed. Check logs for details.")

    def _notify(self, msg: str):
        """Show notification in status bar."""
        if hasattr(self.app, '_sb_status'):
            self.app.after(0, lambda: self.app._sb_status.config(text=msg))


def create_updater(app_dir: str) -> DownpourUpdater:
    """Factory function to create updater."""
    return DownpourUpdater(app_dir)


def integrate_updater(app) -> DownpourUpdater:
    """Integrate updater into main app."""
    updater = DownpourUpdater(app._DOWNPOUR_DIR if hasattr(app, '_DOWNPOUR_DIR') else os.getcwd())
    ui = UpdaterUI(app, updater)

    # Add to app
    app.updater = updater
    app.updater_ui = ui

    # Add to Tools tab or menu
    if hasattr(app, '_build_tools_tab'):
        original_build = app._build_tools_tab

        def wrapped_build():
            original_build()
            # Add update section to tools tab
            try:
                ui.add_update_button(app._tools_toolbar if hasattr(app, '_tools_toolbar') else app)
            except Exception:
                pass

        app._build_tools_tab = wrapped_build

    return updater


# Standalone update check (for CLI/launcher)
def check_for_updates_cli(app_dir: str) -> Dict[str, Any]:
    """CLI-friendly update check."""
    updater = DownpourUpdater(app_dir)
    return updater.check_for_updates()


if __name__ == "__main__":
    # Test update check
    import sys
    dir_path = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    result = check_for_updates_cli(dir_path)
    print(json.dumps(result, indent=2))