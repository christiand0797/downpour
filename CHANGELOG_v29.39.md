# Downpour v29.39 - Titanium Edition Release Notes

## Release Date: 2026-08-11

## Overview
v29.39 Titanium Edition represents a major enhancement to the OSINT4ALL security suite, integrating advanced OSINT data sources, enhanced threat detection capabilities, and comprehensive real-time performance metrics.

---

## New Features

### 1. Advanced System Metrics (Performance Tab)
Added 12 new real-time gauges to the Performance tab for deeper system visibility:

#### Advanced System Metrics (Row 8)
- **LOAD 1M/5M/15M**: Unix-style load averages (emulated on Windows)
- **MEM FRAG**: Memory fragmentation percentage
- **DNS LATENCY**: DNS resolution latency in milliseconds

#### Security Metrics (Row 9)
- **BLOCKED CONNS**: Count of blocked network connections
- **SUSPICIOUS PROCS**: Count of suspicious processes detected
- **SEC EVENTS**: Security events logged today
- **DISK QUEUE**: Disk queue depth (I/O pressure indicator)

#### OSINT Metrics (Row 10)
- **OSINT LOOKUPS**: Total OSINT lookups performed
- **OSINT TODAY**: OSINT lookups performed today
- **OSINT CACHE**: OSINT cache hits (efficiency metric)
- **LOAD 15M**: 15-minute load average

### 2. OSINT Integration
Integrated 5 new OSINT data sources for enhanced threat intelligence:

#### GreyNoise
- Internet noise and scanner detection
- Community API integration for IP reputation
- Classification: noise/malicious/unknown/benign

#### AbuseIPDB
- IP reputation and abuse reporting
- Blacklist integration (10,000 IP limit)
- Abuse confidence scoring

#### Shodan
- Internet-connected device intelligence
- Open port detection
- Vulnerability scanning
- ISP/Organization identification

#### Censys
- Internet-wide scanning data
- Service detection
- Risk scoring

#### URLScan.io
- URL analysis and scanning
- Malware URL detection
- Recent scan history

### 3. Enhanced Network Monitoring
Added OSINT reputation checking to network connection analysis:

- **Composite Threat Scoring**: 0-100 score based on multiple OSINT sources
- **Threat Level Classification**: SAFE/LOW/MEDIUM/HIGH/CRITICAL
- **Real-time IP Reputation**: Checks GreyNoise, AbuseIPDB, Shodan, Censys on connection
- **Enhanced Alerting**: Detailed OSINT context in security alerts

### 4. Enhanced Process Monitoring
Improved malware detection capabilities:

#### New Suspicious Command Line Patterns
- `invoke-expression` - PowerShell execution
- `iex` - PowerShell invoke-expression alias
- `downloadstring` - PowerShell download
- `webclient` - .NET web download
- `http://` / `https://` - Direct URLs in command line

#### Process Hollowing Detection
- Suspended main thread detection (placeholder for future enhancement)
- Enhanced memory anomaly detection

---

## API Configuration

### New API Keys Required
The following API keys can be configured in `threat_intelligence.py`:

```python
self.api_keys = {
    'greynoise': '',  # Get from greynoise.io
    'shodan': '',     # Get from shodan.io
    'abuseipdb': '',  # Get from abuseipdb.com
    'censys': '',     # Get from censys.io
    'urlscan': '',    # Get from urlscan.io
}
```

### API Key Registration
- **GreyNoise**: https://greynoise.io (Community API is free)
- **Shodan**: https://account.shodan.io/register (Free tier available)
- **AbuseIPDB**: https://www.abuseipdb.com/register (Free tier available)
- **Censys**: https://search.censys.io/signup (Free tier available)
- **URLScan.io**: https://urlscan.io/app/signup (Free tier available)

---

## Performance Improvements

### HardwareMonitor Enhancements
- **Load Average Calculation**: Unix-style load averages emulated on Windows
- **Memory Fragmentation**: Real-time fragmentation percentage calculation
- **Disk Queue Depth**: I/O pressure monitoring using delta calculation
- **DNS Latency**: Simple DNS resolution latency test (8.8.8.8)
- **Security Metrics Integration**: Cross-module metric collection
- **OSINT Metrics Tracking**: Lookup counting and cache hit tracking

### Connection Pooling
- Shared HTTP session with keep-alive for threat intelligence feeds
- Connection pool: 10 keep-alive, max 20 connections
- Reduced API call overhead

---

## Security Enhancements

### Network Threat Detection
- OSINT reputation checking integrated into connection analysis
- Composite threat scoring algorithm
- Enhanced alerting with OSINT context
- GreyNoise classification integration
- AbuseIPDB abuse confidence tracking
- Shodan vulnerability counting
- Censys risk scoring

### Process Threat Detection
- Additional suspicious command line patterns
- Enhanced PowerShell obfuscation detection
- Web download detection in command lines
- Process hollowing detection improvements

---

## Database Schema Changes

### Threat Intelligence Database
No schema changes required. Existing tables support new OSINT data:
- `malicious_ips` - Stores IP reputation data
- `malicious_domains` - Stores domain reputation data
- `malware_hashes` - Stores hash reputation data
- `feed_updates` - Tracks feed update status

---

## Feed Update Intervals

New OSINT feeds with configured update intervals:

| Feed | Priority | Update Interval | API Required |
|------|----------|-----------------|--------------|
| GreyNoise | High | 1 hour | Yes |
| AbuseIPDB | High | 1 hour | Yes |
| URLScan.io | High | 30 minutes | Yes |
| Shodan | Medium | 24 hours | Yes |
| Censys | Medium | 24 hours | Yes |

---

## Known Limitations

### GreyNoise Community API
- Requires per-IP lookups (bulk integration placeholder)
- Rate limited without API key

### Shodan/Censys
- Requires API keys for full functionality
- Free tier has rate limits

### OSINT Metrics
- Lookup counters require initialization in main application
- Cache hit tracking depends on cache implementation

---

## Compatibility

### Python Version
- Requires Python 3.8+

### Dependencies
- `psutil` - System metrics
- `requests` - HTTP requests for OSINT APIs
- `pynvml` - GPU monitoring (optional)
- `wmi` - Windows-specific metrics (optional)

### Platform
- Primary: Windows 10/11
- Linux: Partial support (load averages native, WMI not available)

---

## Migration Guide

### From v29.38 to v29.39

1. **Update API Keys**: Add new OSINT API keys to configuration
2. **Performance Tab**: New gauges will appear automatically
3. **Network Monitoring**: OSINT reputation checking enabled by default
4. **Process Monitoring**: New suspicious patterns active immediately

### Configuration Changes
No configuration file changes required. API keys can be set in `threat_intelligence.py` or via environment variables in future versions.

---

## Bug Fixes

### HardwareMonitor
- Fixed load average calculation on Windows (emulated from CPU %)
- Fixed memory fragmentation calculation edge cases
- Fixed disk queue depth delta calculation

### Network Monitor
- Fixed OSINT reputation checking error handling
- Fixed composite threat scoring overflow

### Threat Intelligence
- Fixed feed update dispatch for new OSINT sources
- Fixed API key validation for new sources

---

## Future Enhancements

### Planned for v29.40
- Bulk GreyNoise integration
- Suspended thread detection (process hollowing)
- OSINT metrics persistence
- API key management UI
- Real-time OSINT feed visualization

---

## Credits

### OSINT Sources
- GreyNoise Community API
- AbuseIPDB
- Shodan
- Censys
- URLScan.io

### Inspiration
- OSINT4ALL Start.me resource collection
- PhantomSignal framework
- ioclib library
- Analyst-Tool

---

## Support

For issues, questions, or contributions:
- GitHub: https://github.com/christiand0797/downpour
- Documentation: See inline code comments and module docstrings

---

## License

See LICENSE file for details.

---

**End of v29.39 Release Notes**
