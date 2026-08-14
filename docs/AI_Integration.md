# AI/ML Integration

## Status

| Module | Imported in v29? | Status |
|--------|-----------------|--------|
| `ai_security_engine.py` | No | Standalone — not wired into main app |
| `ml_behavioral_analyzer.py` | No | Standalone — behavioral baseline + anomaly scoring |
| `ml_optimization_engine.py` | No | Standalone — performance tuning (duplicates inline ML) |
| `sklearn` (stub) | Yes (try/except) | Optional — IsolationForest, RandomForestClassifier, MLPClassifier, TfidfVectorizer, StandardScaler |
| `browser_protection.py` | No | **CONSOLIDATED v29.30** — extension manifest risk scoring + browser KEV match now inline in `downpour_v29_titanium.py` (`_scan_browser_extensions` / `_browser_cve_check` / `_browser_ext_dir`) reusing `CisaKevEngine` |
| `advanced_device_profiler.py` | No | **DECLINED** — evasion/anti-security toolkit (bypass-capability analysis); deliberately not wired in |
| `revolutionary_enhancements/` | Yes (try/except) | Optional — quantum/neural placeholders |

## In-app ML features (when sklearn available)

- **Anomaly detection**: IsolationForest used for process/network behavior scoring
- **Threat classification**: RandomForestClassifier for file/process threat scoring
- **NLP threat analysis**: TfidfVectorizer + MLPClassifier for text-based threat classification
- **Fallback**: Weighted heuristic scoring when sklearn is unavailable

## GPU acceleration

- NVIDIA GPU detected via `nvidia-ml-py` (nvml bindings)
- Used for parallel scan acceleration when available
- Graceful fallback to CPU-only mode

## Notes

- All AI/ML imports are guarded by `try/except ImportError` — the app runs fully without them
- Python 3.15.0a6 has no pre-built wheels for scikit-learn; build from source requires a C compiler
- The standalone `_ai` and `_ml` modules contain experimental features not yet integrated
