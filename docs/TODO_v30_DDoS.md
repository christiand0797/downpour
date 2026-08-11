# Downpour v30 — DDoS / Network Protection Enhancement Checklist

## Scope
Additive, safe, high-value DDoS/network-defense enhancements on top of the existing
SYN-flood / packet-capture / firewall-block infrastructure in `downpour_v29_titanium.py`.

## Steps
- [ ] 1. **Enhanced DDoS detection engine**
      - Add `_ddos_init()` state tracker (per-IP connection/SYN/ICMP/UDP rates, timestamps).
      - Add `_ddos_analyze_connections()` — aggregate + per-IP connection-flood detection.
      - Add `_ddos_analyze_icmp_udp()` — ICMP echo / UDP flood heuristics via netstat & psutil.
      - Add `_ddos_classify(ip, count, threshold)` — LOW/MEDIUM/HIGH/CRITICAL severity.
      - Wire into existing `_on_network_alert` / `_ddos_block_ip` flow (respect whitelist + block cap).
- [ ] 2. **Persistent DDoS blocklist**
      - Add `_ddos_load_blocklist()` / `_ddos_save_blocklist()` (JSON in `downpour_data/`).
      - Add block expiry timestamps; auto-unblock expired entries.
- [ ] 3. **Threat-intel correlation**
      - Add `_ddos_reputation(ip)` — optional lookup against existing threat-feed data,
        returns a reputation score (0-100) + label, with graceful fallback.
      - Incorporate reputation into severity classification.
- [ ] 4. **Network tab UI**
      - Add buttons: "🛡 DDoS Shield", "📊 Rate Monitor", "🚫 Block All Flooders", "📄 Export DDoS Report".
      - Add tooltips via `_make_button`.
      - Add handlers: `_ddos_shield`, `_ddos_rate_monitor_ui`, `_ddos_block_all_flooders`, `_ddos_export_report`.
- [ ] 5. **Docs**
      - Update `README.md` feature table + `_WORKLOG.md` + `docs/CHANGELOG.md`.
- [ ] 6. **Verify**
      - `python -m py_compile downpour_v29_titanium.py` passes.
      - No import errors; features degrade gracefully if psutil/requests missing.
