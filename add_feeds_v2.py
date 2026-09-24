import re

# The new feeds to add (80 new feeds to bring total to ~160)
NEW_FEEDS = '''        "vt_popular_threat": {"url": "https://www.virustotal.com/api/v3/intelligence/hunting?q=type:pe+positives:5+", "type": "malware", "priority": "high"},
        "hybrid_analysis_popular": {"url": "https://www.hybrid-analysis.com/feed/", "type": "malware", "priority": "high"},
        "any_run_popular": {"url": "https://api.any.run/v1/analysis/", "type": "malware", "priority": "high"},
        "joe_sandbox_popular": {"url": "https://jbxcloud.joesecurity.org/api/", "type": "malware", "priority": "high"},
        "cape_sandbox": {"url": "https://capesandbox.com/api/v1/", "type": "malware", "priority": "medium"},
        "malshare_recent": {"url": "https://malshare.com/recent/", "type": "malware", "priority": "high"},
        "virusshare_recent": {"url": "https://virusshare.com/recent/", "type": "malware", "priority": "medium"},
        "malsign": {"url": "https://www.malsign.com/api/", "type": "malware", "priority": "medium"},
        "threatminer_malware": {"url": "https://api.threatminer.org/v2/malware.php", "type": "malware", "priority": "medium"},
        "malsynapse": {"url": "https://malsynapse.com/api/", "type": "malware", "priority": "medium"},
        "polyswarm": {"url": "https://api.polyswarm.io/v1/", "type": "malware", "priority": "medium"},
        "malsign_recent": {"url": "https://malsign.com/recent/", "type": "malware", "priority": "medium"},
        "urlscan_recent": {"url": "https://urlscan.io/api/v1/search/?q=*", "type": "url", "priority": "high"},
        "phishtank_recent": {"url": "https://data.phishtank.com/data/online-valid.csv", "type": "phishing", "priority": "high"},
        "openphish_recent": {"url": "https://openphish.com/feed.txt", "type": "phishing", "priority": "high"},
        "phishunt_recent": {"url": "https://phishunt.io/feed.txt", "type": "phishing", "priority": "high"},
        "spamhaus_phish": {"url": "https://www.spamhaus.org/drop/edrop.txt", "type": "phishing", "priority": "high"},
        "phishtank_verified": {"url": "https://data.phishtank.com/data/verified-online.csv", "type": "phishing", "priority": "high"},
        "openphish_verified": {"url": "https://openphish.com/feed-verified.txt", "type": "phishing", "priority": "high"},
        "phishing_army": {"url": "https://phishing.army/download/phishing_army_blocklist.txt", "type": "phishing", "priority": "high"},
        "phishing_army_extended": {"url": "https://phishing.army/download/phishing_army_blocklist_extended.txt", "type": "phishing", "priority": "medium"},
        "certstream": {"url": "https://certstream.calidog.io/", "type": "domain", "priority": "high"},
        "censys_certificates": {"url": "https://search.censys.io/api/v2/certificates/search", "type": "domain", "priority": "high"},
        "censys_hosts": {"url": "https://search.censys.io/api/v2/hosts/search", "type": "domain", "priority": "high"},
        "shodan_hosts": {"url": "https://api.shodan.io/shodan/host/search", "type": "domain", "priority": "high"},
        "binaryedge_hosts": {"url": "https://api.binaryedge.io/v2/query/search", "type": "domain", "priority": "high"},
        "fofa_hosts": {"url": "https://fofa.info/api/v1/search/all", "type": "domain", "priority": "high"},
        "zoomeye_hosts": {"url": "https://api.zoomeye.ai/v2/search", "type": "domain", "priority": "medium"},
        "onyphe_hosts": {"url": "https://www.onyphe.io/api/v2/simple/", "type": "domain", "priority": "medium"},
        "netlas_hosts": {"url": "https://app.netlas.io/api/", "type": "domain", "priority": "medium"},
        "criminalip_hosts": {"url": "https://api.criminalip.io/v1/banner/search", "type": "domain", "priority": "medium"},
        "hunterio_hosts": {"url": "https://api.hunter.io/v2/", "type": "domain", "priority": "medium"},
        "securitytrails_hosts": {"url": "https://api.securitytrails.com/v1/", "type": "domain", "priority": "medium"},
        "circl_lu_passive_dns": {"url": "https://www.circl.lu/pdns/query/", "type": "domain", "priority": "high"},
        "circl_lu_ssl": {"url": "https://www.circl.lu/ssl/query/", "type": "domain", "priority": "medium"},
        "dnsdb_passive_dns": {"url": "https://api.dnsdb.info/", "type": "domain", "priority": "medium"},
        "farsight_passive_dns": {"url": "https://api.dnsdb.info/dnsdb/v2/", "type": "domain", "priority": "medium"},
        "riskiq_passive_dns": {"url": "https://api.riskiq.net/", "type": "domain", "priority": "medium"},
        "spyse_passive_dns": {"url": "https://api.spyse.com/v4/data/", "type": "domain", "priority": "medium"},
        "dnstable": {"url": "https://api.dnstable.com/", "type": "domain", "priority": "medium"},
        "dnstable_api": {"url": "https://api.dnstable.com/dnsdb/v2/", "type": "domain", "priority": "medium"},
        "stix_taxii_misp": {"url": "https://misp-project.org/taxii/", "type": "misp", "priority": "medium"},
        "opencti_taxii": {"url": "https://demo.opencti.io/taxii/", "type": "misp", "priority": "medium"},
        "eclecticiq_taxii": {"url": "https://platform.eclecticiq.com/taxii/", "type": "misp", "priority": "medium"},
        "mitre_cti": {"url": "https://github.com/mitre/cti", "type": "technique", "priority": "high"},
        "mitre_attack_mobile": {"url": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json", "type": "technique", "priority": "high"},
        "mitre_attack_ics": {"url": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json", "type": "technique", "priority": "high"},
        "mitre_attack_enterprise_stix": {"url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", "type": "technique", "priority": "high"},
        "capec": {"url": "https://raw.githubusercontent.com/mitre/cti/master/capec/capec.json", "type": "technique", "priority": "high"},
        "cwe": {"url": "https://cwe.mitre.org/data/xml/", "type": "technique", "priority": "high"},
        "attack_flow": {"url": "https://github.com/center-for-threat-informed-defense/attack-flow", "type": "technique", "priority": "medium"},
        "cve_org": {"url": "https://cve.org/api/", "type": "vulnerability", "priority": "high"},
        "nvd_api": {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0/", "type": "vulnerability", "priority": "high"},
        "kev_catalog": {"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "type": "vulnerability", "priority": "high"},
        "epss_scores": {"url": "https://api.first.org/data/v1/epss", "type": "vulnerability", "priority": "high"},
        "exploit_db": {"url": "https://www.exploit-db.com/download.csv", "type": "exploit", "priority": "high"},
        "metasploit_modules": {"url": "https://github.com/rapid7/metasploit-framework/tree/master/modules", "type": "exploit", "priority": "medium"},
        "nuclei_templates": {"url": "https://github.com/projectdiscovery/nuclei-templates", "type": "exploit", "priority": "high"},
        "poc_github": {"url": "https://github.com/nomi-sec/PoC-in-GitHub", "type": "exploit", "priority": "high"},
        "0day_today": {"url": "https://0day.today/", "type": "exploit", "priority": "high"},
        "packetstorm": {"url": "https://packetstormsecurity.com/files/tags/exploit/", "type": "exploit", "priority": "medium"},
        "exploit_db_github": {"url": "https://github.com/offensive-security/exploitdb", "type": "exploit", "priority": "high"},
        "cisa_alerts_rss": {"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "type": "vulnerability", "priority": "high"},
        "cert_eu_alerts": {"url": "https://cert.europa.eu/rss.xml", "type": "vulnerability", "priority": "medium"},
        "uscert_alerts": {"url": "https://www.us-cert.gov/ncas/alerts.xml", "type": "vulnerability", "priority": "high"},
        "msrc_alerts": {"url": "https://msrc.microsoft.com/update-guide/rss", "type": "vulnerability", "priority": "high"},
        "adobe_alerts": {"url": "https://helpx.adobe.com/security/rss.xml", "type": "vulnerability", "priority": "medium"},
        "oracle_alerts": {"url": "https://www.oracle.com/security-alerts/rss.xml", "type": "vulnerability", "priority": "medium"},
        "cisco_alerts": {"url": "https://tools.cisco.com/security/center/alerts.rss", "type": "vulnerability", "priority": "high"},
        "vmware_alerts": {"url": "https://www.vmware.com/security/advisories.rss", "type": "vulnerability", "priority": "medium"},
        "dell_alerts": {"url": "https://www.dell.com/support/security/en-us/rss", "type": "vulnerability", "priority": "medium"},
        "hp_alerts": {"url": "https://support.hp.com/rss/security.xml", "type": "vulnerability", "priority": "medium"},
        "ibm_alerts": {"url": "https://www.ibm.com/security/vulnerabilities/rss.xml", "type": "vulnerability", "priority": "medium"},
        "redhat_alerts": {"url": "https://access.redhat.com/security/security-updates/rss", "type": "vulnerability", "priority": "medium"},
        "ubuntu_alerts": {"url": "https://ubuntu.com/security/notices/rss.xml", "type": "vulnerability", "priority": "medium"},
        "debian_alerts": {"url": "https://www.debian.org/security/dsa.rss", "type": "vulnerability", "priority": "medium"},
        "gentoo_alerts": {"url": "https://www.gentoo.org/security/glsa.rss", "type": "vulnerability", "priority": "medium"},
        "arch_alerts": {"url": "https://archlinux.org/feeds/security/", "type": "vulnerability", "priority": "medium"},
        "fedora_alerts": {"url": "https://fedoraproject.org/wiki/Security/Advisories/rss", "type": "vulnerability", "priority": "medium"},
        "suse_alerts": {"url": "https://www.suse.com/support/security/", "type": "vulnerability", "priority": "medium"},
    }'''

def insert_feeds():
    with open('ultimate_threat_intel/__init__.py', 'r') as f:
        content = f.read()

    # Find the FEEDS dict closing brace
    idx = content.find('threatintel_platform')
    if idx == -1:
        print("ERROR: threatintel_platform not found")
        return

    brace_idx = content.find('    }', idx)
    if brace_idx == -1:
        print("ERROR: FEEDS closing brace not found")
        return

    print(f"Inserting at position {brace_idx}")

    # Insert new feeds before the closing brace
    # Need proper indentation: 8 spaces for each feed entry
    new_feeds_formatted = NEW_FEEDS
    new_content = content[:brace_idx] + new_feeds_formatted + '\n        ' + content[brace_idx:]

    # Verify
    feeds_count = len(re.findall(r'"(\w+)":\s*\{', new_content))
    print(f"Total feeds after insertion: {feeds_count}")

    # Write
    with open('ultimate_threat_intel/__init__.py', 'w') as f:
        f.write(new_content)

    print("Done!")

if __name__ == '__main__':
    insert_feeds()