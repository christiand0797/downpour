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
import re
import stat
from pathlib import Path
from pathlib import PurePosixPath
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlsplit

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
MAX_UPDATE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_UPDATE_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_UPDATE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_UPDATE_ARCHIVE_ENTRIES = 10000
MAX_UPDATE_COMPRESSION_RATIO = 250
MAX_GITHUB_REDIRECTS = 5
GITHUB_DOWNLOAD_HOSTS = {"api.github.com", "github.com", "codeload.github.com"}

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

    @staticmethod
    def _validate_github_url(url: str) -> str:
        """Allow only credential-free HTTPS URLs on the GitHub download hosts."""
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError("GitHub update URL is invalid")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("GitHub update URL is malformed") from exc
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.hostname.lower() not in GITHUB_DOWNLOAD_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port not in (None, 443)
        ):
            raise ValueError("Update downloads must remain on an approved HTTPS GitHub host")
        return url

    def _open_github_stream(self, url: str, timeout: int):
        """Open an update URL without allowing arbitrary or insecure redirects."""
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("requests not installed")
        current_url = self._validate_github_url(url)
        for redirect_count in range(MAX_GITHUB_REDIRECTS + 1):
            response = requests.get(
                current_url,
                headers={"Accept-Encoding": "identity", "User-Agent": "Downpour-Updater"},
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise ValueError("GitHub update redirect omitted its destination")
                if redirect_count >= MAX_GITHUB_REDIRECTS:
                    raise ValueError("GitHub update exceeded the redirect limit")
                current_url = self._validate_github_url(urljoin(current_url, location))
                continue
            if 300 <= response.status_code < 400:
                response.close()
                raise ValueError(f"Unexpected GitHub update redirect: {response.status_code}")
            try:
                self._validate_github_url(response.url or current_url)
            except Exception:
                response.close()
                raise
            return response
        raise ValueError("GitHub update exceeded the redirect limit")

    @staticmethod
    def _cache_bounded_response(response, max_bytes: int):
        """Read and cache a small HTTP response while preserving requests APIs."""
        try:
            encoding = str(response.headers.get("Content-Encoding", "identity")).lower().strip()
            if encoding not in ("", "identity"):
                raise ValueError(f"Unsupported update response encoding: {encoding[:32]}")
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    declared = int(declared)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Update response has an invalid Content-Length") from exc
                if declared < 0 or declared > max_bytes:
                    raise ValueError(f"Update response exceeds the {max_bytes}-byte limit")
            data = bytearray()
            for chunk in response.raw.stream(64 * 1024, decode_content=False):
                if not chunk:
                    continue
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise ValueError(f"Update response exceeds the {max_bytes}-byte limit")
            if declared is not None and len(data) != declared:
                raise ValueError("Update response is truncated")
            response.raise_for_status()
            response.close()
            response._content = bytes(data)
            response._content_consumed = True
            return response
        except Exception:
            response.close()
            raise

    @staticmethod
    def _safe_extract_update(archive_path: str, destination: Path) -> Path:
        """Extract only whitelisted regular files from one safe GitHub zip root."""
        wanted = {PurePosixPath(item).as_posix() for item in UPDATE_FILES}
        if any(
            path.is_absolute() or ".." in path.parts or "\\" in item
            for item in UPDATE_FILES
            for path in (PurePosixPath(item),)
        ):
            raise ValueError("Updater file allowlist contains an unsafe path")

        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_UPDATE_ARCHIVE_ENTRIES:
                raise ValueError("Update archive has an invalid number of entries")
            roots = set()
            seen_paths = set()
            expanded_total = 0
            selected = {}
            for info in entries:
                name = info.filename
                if not name or "\\" in name or "\x00" in name:
                    raise ValueError("Update archive contains an unsafe path")
                path = PurePosixPath(name)
                if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
                    raise ValueError("Update archive contains an unsafe path")
                if path.parts and ":" in path.parts[0]:
                    raise ValueError("Update archive contains a drive-qualified path")
                if len(path.parts) < 2:
                    if info.is_dir() and len(path.parts) == 1:
                        roots.add(path.parts[0])
                        continue
                    raise ValueError("Update archive is missing its repository root")
                roots.add(path.parts[0])
                normalized = path.as_posix().rstrip("/").casefold()
                if normalized in seen_paths:
                    raise ValueError("Update archive contains duplicate paths")
                seen_paths.add(normalized)

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("Update archive contains a non-regular file")
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.file_size > MAX_UPDATE_MEMBER_BYTES:
                    raise ValueError("Update archive member exceeds its size limit")
                expanded_total += info.file_size
                if expanded_total > MAX_UPDATE_EXPANDED_BYTES:
                    raise ValueError("Update archive exceeds its expanded size limit")
                if info.file_size and (
                    info.compress_size <= 0
                    or info.file_size / info.compress_size > MAX_UPDATE_COMPRESSION_RATIO
                ):
                    raise ValueError("Update archive member has an unsafe compression ratio")
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                if relative in wanted:
                    selected[relative] = info

            if len(roots) != 1:
                raise ValueError("Update archive must contain exactly one repository root")
            if "downpour_v29_titanium.py" not in selected:
                raise ValueError("Update archive is missing the main application")

            root_dir = destination / next(iter(roots))
            root_dir.mkdir(parents=True, exist_ok=True)
            extracted_total = 0
            for relative, info in selected.items():
                output = root_dir.joinpath(*PurePosixPath(relative).parts)
                resolved_output = output.resolve()
                if not resolved_output.is_relative_to(root_dir.resolve()):
                    raise ValueError("Update archive path escapes its staging directory")
                output.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info, "r") as source, output.open("wb") as target:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        extracted_total += len(chunk)
                        if written > MAX_UPDATE_MEMBER_BYTES or extracted_total > MAX_UPDATE_EXPANDED_BYTES:
                            raise ValueError("Update archive exceeded its extraction limit")
                        target.write(chunk)
                if written != info.file_size:
                    raise ValueError("Update archive member size does not match its directory")
            return root_dir

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
            resp = self._open_github_stream(url, timeout=15)
            resp.headers.setdefault("Content-Type", "application/json")
            resp = self._cache_bounded_response(resp, 2 * 1024 * 1024)
            release = resp.json()

            self.latest_version = release.get("tag_name", "").lstrip("v")
            if not re.fullmatch(r"\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", self.latest_version):
                raise ValueError("GitHub returned an invalid release version")
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

        zip_path = None
        try:
            # Construct a known GitHub API URL instead of trusting a release's
            # user-controlled zipball_url field.
            if not REQUESTS_AVAILABLE:
                raise RuntimeError("requests not installed")
            if not self.latest_version or not re.fullmatch(
                r"\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", self.latest_version
            ):
                raise ValueError("No valid release version is selected")
            from urllib.parse import quote
            zip_url = f"{GITHUB_API}/repos/{GITHUB_REPO}/zipball/v{quote(self.latest_version, safe='.-')}"
            resp = self._open_github_stream(zip_url, timeout=60)
            try:
                resp.raise_for_status()
                content_encoding = str(resp.headers.get("Content-Encoding", "identity")).lower().strip()
                if content_encoding not in ("", "identity"):
                    raise ValueError(f"Unsupported update archive encoding: {content_encoding[:32]}")
                declared_length = resp.headers.get("Content-Length")
                total_size = 0
                if declared_length is not None:
                    try:
                        total_size = int(declared_length)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("Update archive has an invalid Content-Length") from exc
                    if total_size < 0 or total_size > MAX_UPDATE_ARCHIVE_BYTES:
                        raise ValueError("Update archive exceeds the download size limit")

                downloaded = 0
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    zip_path = tmp.name
                    for chunk in resp.raw.stream(64 * 1024, decode_content=False):
                        if self._stop_event.is_set():
                            return False
                        if not chunk:
                            continue
                        downloaded += len(chunk)
                        if downloaded > MAX_UPDATE_ARCHIVE_BYTES:
                            raise ValueError("Update archive exceeds the download size limit")
                        tmp.write(chunk)
                        if total_size and progress_callback:
                            progress = 0.1 + (downloaded / total_size) * 0.6
                            progress_callback(progress, f"Downloaded {downloaded}/{total_size} bytes")
                if total_size and downloaded != total_size:
                    raise ValueError("Update archive download was truncated")
            finally:
                resp.close()

            self._notify("extracting", 0.7, "Validating and extracting update...")

            # Validate the whole archive before copying any file into the app.
            with tempfile.TemporaryDirectory() as extract_dir:
                repo_dir = self._safe_extract_update(zip_path, Path(extract_dir))

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

                # Copy new files and restore touched files if any copy fails.
                self._notify("installing", 0.8, "Installing update...")
                touched = []
                try:
                    for f in UPDATE_FILES:
                        src = repo_dir / f
                        if src.exists():
                            dst = self.app_dir / f
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            touched.append(f)
                            shutil.copy2(src, dst)
                except Exception:
                    for f in reversed(touched):
                        dst = self.app_dir / f
                        backup = backup_dir / f
                        try:
                            if backup.exists():
                                shutil.copy2(backup, dst)
                            elif dst.exists():
                                dst.unlink()
                        except OSError:
                            logger.exception("Failed to roll back partially installed file: %s", f)
                    raise

                # Create directories
                for d in UPDATE_DIRS:
                    (self.app_dir / d).mkdir(parents=True, exist_ok=True)

                # Update version file
                version_file = self.app_dir / "VERSION"
                version_file.write_text(f"{self.latest_version}\n{datetime.now().isoformat()}")

                # Update requirements
                self._notify("updating_deps", 0.9, "Updating dependencies...")
                self._update_dependencies()

            self._notify("complete", 1.0, f"Updated to v{self.latest_version}")
            return True

        except Exception as e:
            logger.error(f"Update failed: {e}")
            self._notify("error", 0, f"Update failed: {e}")
            return False
        finally:
            if zip_path:
                try:
                    os.unlink(zip_path)
                except OSError:
                    pass

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
