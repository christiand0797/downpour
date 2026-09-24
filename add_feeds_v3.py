import re

# Define new feeds as a list of tuples (name, url, type, priority)
NEW_FEEDS_DATA = [
    ("vt_popular_threat", "https://www.virustotal.com/api/v3/intelligence/hunting?q=type:pe+positives:5+", "malware", "high"),
    ("hybrid_analysis_popular", "https://www.hybrid-analysis.com/feed/", "malware", "high"),
    ("any_run_popular", "https://api.any.run/v1/analysis/", "malware", "high"),
    ("joe_sandbox_popular", "https://jbxcloud.joesecurity.org/api/", "malware", "high"),
    ("cape_sandbox", "https://capesandbox.com/api/v1/", "malware", "medium"),
    ("malshare_recent", "https://malshare.com/recent/", "malware", "high"),
    ("virusshare_recent", "https://virusshare.com/recent/", "malware", "medium"),
    ("malsign", "https://www.malsign.com/api/", "malware", "medium"),
    ("threatminer_malware", "https://api.threatminer.org/v2/malware.php", "malware", "medium"),
    ("malsynapse", "https://malsynapse.com/api/", "malware", "medium"),
    ("polyswarm", "https://api.polyswarm.io/v1/", "malware", "medium"),
    ("malsign_recent", "https://malsign.com/recent/", "malware", "medium"),
    ("urlscan_recent", "https://urlscan.io/api/v1/search/?q=*", "url", "high"),
    ("phishtank_recent", "https://data.phishtank.com/data/online-valid.csv", "phishing", "high"),
    ("openphish_recent", "https://openphish.com/feed.txt", "phishing", "high"),
    ("phishunt_recent", "https://phishunt.io/feed.txt", "phishing", "high"),
    ("spamhaus_phish", "https://www.spamhaus.org/drop/edrop.txt", "phishing", "high"),
    ("phishtank_verified", "https://data.phishtank.com/data/verified-online.csv", "phishing", "high"),
    ("openphish_verified", "https://openphish.com/feed-verified.txt", "phishing", "high"),
    ("phishing_army", "https://phishing.army/download/phishing_army_blocklist.txt", "phishing", "high"),
    ("phishing_army_extended", "https://phishing.army/download/phishing_army_blocklist_extended.txt", "phishing", "medium"),
    ("certstream", "https://certstream.calidog.io/", "domain", "high"),
    ("censys_certificates", "https://search.censys.io/api/v2/certificates/search", "domain", "high"),
    ("censys_hosts", "https://search.censys.io/api/v2/hosts/search", "domain", "high"),
    ("shodan_hosts", "https://api.shodan.io/shodan/host/search", "domain", "high"),
    ("binaryedge_hosts", "https://api.binaryedge.io/v2/query/search", "domain", "high"),
    ("fofa_hosts", "https://fofa.info/api/v1/search/all", "domain", "high"),
    ("zoomeye_hosts", "https://api.zoomeye.ai/v2/search", "domain", "medium"),
    ("onyphe_hosts", "https://www.onyphe.io/api/v2/simple/", "domain", "medium"),
    ("netlas_hosts", "https://app.netlas.io/api/", "domain", "medium"),
    ("criminalip_hosts", "https://api.criminalip.io/v1/banner/search", "domain", "medium"),
    ("hunterio_hosts", "https://api.hunter.io/v2/", "domain", "medium"),
    ("securitytrails_hosts", "https://api.securitytrails.com/v1/", "domain", "medium"),
    ("circl_lu_passive_dns", "https://www.circl.lu/pdns/query/", "domain", "high"),
    ("circl_lu_ssl", "https://www.circl.lu/ssl/query/", "domain", "medium"),
    ("dnsdb_passive_dns", "https://api.dnsdb.info/", "domain", "medium"),
    ("farsight_passive_dns", "https://api.dnsdb.info/dnsdb/v2/", "domain", "medium"),
    ("riskiq_passive_dns", "https://api.riskiq.net/", "domain", "medium"),
    ("spyse_passive_dns", "https://api.spyse.com/v4/data/", "domain", "medium"),
    ("dnstable", "https://api.dnstable.com/", "domain", "medium"),
    ("dnstable_api", "https://api.dnstable.com/dnsdb/v2/", "domain", "medium"),
    ("stix_taxii_misp", "https://misp-project.org/taxii/", "misp", "medium"),
    ("opencti_taxii", "https://demo.opencti.io/taxii/", "misp", "medium"),
    ("eclecticiq_taxii", "https://platform.eclecticiq.com/taxii/", "misp", "medium"),
    ("mitre_cti", "https://github.com/mitre/cti", "technique", "high"),
    ("mitre_attack_mobile", "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json", "technique", "high"),
    ("mitre_attack_ics", "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json", "technique", "high"),
    ("mitre_attack_enterprise_stix", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", "technique", "high"),
    ("capec", "https://raw.githubusercontent.com/mitre/cti/master/capec/capec.json", "technique", "high"),
    ("cwe", "https://cwe.mitre.org/data/xml/", "technique", "high"),
    ("attack_flow", "https://github.com/center-for-threat-informed-defense/attack-flow", "technique", "medium"),
    ("cve_org", "https://cve.org/api/", "vulnerability", "high"),
    ("nvd_api", "https://services.nvd.nist.gov/rest/json/cves/2.0/", "vulnerability", "high"),
    ("kev_catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "vulnerability", "high"),
    ("epss_scores", "https://api.first.org/data/v1/epss", "vulnerability", "high"),
    ("exploit_db", "https://www.exploit-db.com/download.csv", "exploit", "high"),
    ("metasploit_modules", "https://github.com/rapid7/metasploit-framework/tree/master/modules", "exploit", "medium"),
    ("nuclei_templates", "https://github.com/projectdiscovery/nuclei-templates", "exploit", "high"),
    ("poc_github", "https://github.com/nomi-sec/PoC-in-GitHub", "exploit", "high"),
    ("0day_today", "https://0day.today/", "exploit", "high"),
    ("packetstorm", "https://packetstormsecurity.com/files/tags/exploit/", "exploit", "medium"),
    ("exploit_db_github", "https://github.com/offensive-security/exploitdb", "exploit", "high"),
    ("cisa_alerts_rss", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "vulnerability", "high"),
    ("cert_eu_alerts", "https://cert.europa.eu/rss.xml", "vulnerability", "medium"),
    ("uscert_alerts", "https://www.us-cert.gov/ncas/alerts.xml", "vulnerability", "high"),
    ("msrc_alerts", "https://msrc.microsoft.com/update-guide/rss", "vulnerability", "high"),
    ("adobe_alerts", "https://helpx.adobe.com/security/rss.xml", "vulnerability", "medium"),
    ("oracle_alerts", "https://www.oracle.com/security-alerts/rss.xml", "vulnerability", "medium"),
    ("cisco_alerts", "https://tools.cisco.com/security/center/alerts.rss", "vulnerability", "high"),
    ("vmware_alerts", "https://www.vmware.com/security/advisories.rss", "vulnerability", "medium"),
    ("dell_alerts", "https://www.dell.com/support/security/en-us/rss", "vulnerability", "medium"),
    ("hp_alerts", "https://support.hp.com/rss/security.xml", "vulnerability", "medium"),
    ("ibm_alerts", "https://www.ibm.com/security/vulnerabilities/rss.xml", "vulnerability", "medium"),
    ("redhat_alerts", "https://access.redhat.com/security/security-updates/rss", "vulnerability", "medium"),
    ("ubuntu_alerts", "https://ubuntu.com/security/notices/rss.xml", "vulnerability", "medium"),
    ("debian_alerts", "https://www.debian.org/security/dsa.rss", "vulnerability", "medium"),
    ("gentoo_alerts", "https://www.gentoo.org/security/glsa.rss", "vulnerability", "medium"),
    ("arch_alerts", "https://archlinux.org/feeds/security/", "vulnerability", "medium"),
    ("fedora_alerts", "https://fedoraproject.org/wiki/Security/Advisories/rss", "vulnerability", "medium"),
    ("suse_alerts", "https://www.suse.com/support/security/", "vulnerability", "medium"),
]

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

    # Build the new feeds string with proper indentation (8 spaces)
    lines = []
    for name, url, ftype, priority in NEW_FEEDS_DATA:
        lines.append(f'        "{name}": {{"url": "{url}", "type": "{ftype}", "priority": "{priority}"}},')

    new_feeds_str = '\n'.join(lines)

    # Insert before the closing brace
    new_content = content[:brace_idx] + new_feeds_str + '\n        ' + content[brace_idx:]

    # Verify syntax
    try:
        compile(new_content, 'ultimate_threat_intel/__init__.py', 'exec')
        print("Syntax OK")
    except SyntaxError as e:
        print(f"Syntax Error: {e}")
        print(f"Error at line {e.lineno}: {e.text}")
        return

    # Count feeds
    feeds_count = len(re.findall(r'"(\w+)":\s*\{', new_content))
    print(f"Total feeds after insertion: {feeds_count}")

    # Write
    with open('ultimate_threat_intel/__init__.py', 'w') as f:
        f.write(new_content)

    print("Done!")

if __name__ == '__main__':
    insert_feeds()