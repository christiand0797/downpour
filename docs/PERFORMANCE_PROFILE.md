# Performance Profiling Results - Downpour v29 Titanium
# Date: 2026-09-22
# Python: 3.15.0a6 (alpha)

## YARA Scanning (yara_x_engine)
- Engine: yara-python fallback (yara-x not available)
- Rulesets: 23
- **500 scans: 0.549s total**
- **Per scan: ~1.10ms**
- **Throughput: ~910 scans/sec**

## Memory Forensics (memory_forensics)
- MemoryForensicsAnalyzer scan on current process (PID):
- **Single scan: ~20-22ms**
- **Avg over 5 runs: 20.85ms**
- Memory regions analyzed: ~2,700
- Risk score calculation: ~17ms (included above)

## PE Analyzer (pe_analyzer)
- notepad.exe: **117ms** (8 sections, 5 suspicious imports, 1 high entropy section, risk=10)
- calc.exe: **27ms** (7 sections, clean, risk=0)
- Batch (2 files): **137ms**
- **Avg single file: ~120ms**

## AI Security Engine (ai_security_engine)
- Running in heuristic mode (scikit-learn not available)
- get_ai_threat_score function: **<0.01ms per call** (very fast, pure Python)
- get_security_insights: **<0.01ms per call**

## Threat Feed Aggregator (threat_feed_aggregator)
- get_statistics: **~1ms**
- 56 feeds available, 56 enabled

## Sensor Hub (sensor_hub)
- Requires start() before get_last_snapshot() returns data
- Stats available immediately

## Summary - Hot Path Performance
| Component | Per Operation | Notes |
|-----------|---------------|-------|
| YARA Scan | ~1.1ms | Fast, good for batch scanning |
| Memory Forensics | ~21ms | Per-process, good for periodic checks |
| PE Analysis | ~120ms | Per-file, acceptable for on-demand |
| AI Threat Scoring | <0.01ms | Extremely fast, heuristic mode |
| Feed Stats | ~1ms | Negligible |

## Optimization Opportunities
1. **PE Analyzer** - Could cache results for repeated scans of same file
2. **Memory Forensics** - Already fast enough for periodic monitoring
3. **YARA** - Very fast, no immediate optimization needed
4. **AI Engine** - Would benefit from scikit-learn for ML-based detection