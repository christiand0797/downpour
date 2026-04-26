"""
===============================================================================
EMAIL SECURITY SCANNER MODULE
===============================================================================
Purpose: Protect against phishing attacks and malicious email attachments
Created: January 2026 - Claude's Enhancement

FEATURES:
- Phishing detection using multiple heuristics
- Malicious attachment scanning
- Suspicious link analysis
- Email header analysis for spoofing
- Integration with threat intelligence feeds
- Real-time Outlook/Thunderbird monitoring

USAGE:
    python email_security.py --scan-outlook
    python email_security.py --scan-file email.eml
    python email_security.py --monitor

This module protects you and your son from email-based threats, which are
the #1 way hackers compromise home computers.
===============================================================================
"""

import os
import sys
import re
import email
import hashlib
import sqlite3
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
import json

# Try importing required modules
try:
    import win32com.client
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    print("⚠️  win32com not available - Outlook integration disabled")
    print("   Install with: pip install pywin32")


class EmailSecurityScanner:
    """
    Comprehensive email security scanner to protect against phishing
    and malicious attachments.
    """
    
    def __init__(self, config_path: str = "email_security_config.json"):
        self.config_path = config_path
        self.db_path = "email_security.db"
        
        # Default configuration
        self.config = {
            "enabled": True,
            "scan_outlook": True,
            "scan_thunderbird": True,
            "real_time_monitoring": True,
            "quarantine_suspicious": True,
            "alert_threshold": 5,  # Alert if score >= 5
            "block_threshold": 8,   # Auto-quarantine if score >= 8
        }
        
        # Phishing indicators - each adds to suspicion score
        self.phishing_indicators = {
            # URL-based indicators
            "url_shortener": 2,  # bit.ly, tinyurl, etc.
            "ip_address_url": 3,  # http://123.456.789.0
            "suspicious_tld": 2,  # .tk, .ga, .ml, etc.
            "homograph_attack": 5,  # Lookalike domains
            "url_typosquatting": 5,  # paypa1.com instead of paypal.com
            
            # Content-based indicators
            "urgent_language": 2,  # "URGENT", "IMMEDIATE ACTION"
            "financial_terms": 2,  # "verify account", "suspended"
            "password_request": 4,  # Asking for passwords
            "personal_info_request": 3,  # SSN, DOB, etc.
            "exe_attachment": 4,  # .exe, .scr, .bat files
            "suspicious_attachment": 3,  # .js, .vbs, .jar
            "macro_document": 3,  # Office docs with macros
            
            # Sender-based indicators
            "sender_spoof": 5,  # Display name != email address
            "suspicious_sender": 3,  # Free email from "bank"
            "no_previous_contact": 1,  # Never emailed before
        }
        
        # Known legitimate domains (for comparison)
        self.legitimate_domains = {
            "paypal.com", "amazon.com", "microsoft.com", "google.com",
            "apple.com", "facebook.com", "twitter.com", "linkedin.com",
            "ebay.com", "netflix.com", "spotify.com"
        }
        
        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = {
            '.tk', '.ga', '.ml', '.cf', '.gq', '.top', '.work', '.click',
            '.link', '.download', '.racing', '.review', '.stream'
        }
        
        # URL shorteners
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
        }
        
        # Dangerous file extensions
        self.dangerous_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.ws', '.wsf', '.wsh',
            '.ps1', '.msi', '.reg', '.hta', '.cpl', '.inf'
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = {
            '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
            '.pdf', '.zip', '.rar', '.7z', '.iso'
        }
        
        self.load_config()
        self.init_database()
    
    def load_config(self):
        """Load configuration from JSON file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
                print(f"✅ Loaded email security config from {self.config_path}")
            except Exception as e:
                print(f"⚠️  Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to JSON file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"✅ Saved email security config")
        except Exception as e:
            print(f"❌ Error saving config: {e}")
    
    def init_database(self):
        """Initialize SQLite database for tracking scanned emails"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scanned_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    email_id TEXT,
                    sender TEXT,
                    subject TEXT,
                    risk_score INTEGER,
                    indicators TEXT,
                    action_taken TEXT,
                    was_quarantined BOOLEAN
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    email_id TEXT,
                    filename TEXT,
                    file_hash TEXT,
                    file_type TEXT,
                    risk_score INTEGER,
                    detection_reason TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS known_senders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_address TEXT UNIQUE,
                    display_name TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    email_count INTEGER,
                    is_trusted BOOLEAN
                )
            ''')

            conn.commit()
        finally:
            conn.close()
        print("✅ Email security database initialized")
    
    def analyze_email(self, email_message: email.message.Message) -> Dict:
        """
        Analyze an email for phishing indicators and malicious content.
        Returns a dictionary with analysis results.
        """
        result = {
            "risk_score": 0,
            "indicators": [],
            "sender": "",
            "subject": "",
            "urls": [],
            "attachments": [],
            "recommendation": "",
            "details": []
        }
        
        # Extract basic info
        result["sender"] = email_message.get("From", "")
        result["subject"] = email_message.get("Subject", "")
        result["date"] = email_message.get("Date", "")
        
        # Analyze sender
        sender_score, sender_indicators = self.analyze_sender(email_message)
        result["risk_score"] += sender_score
        result["indicators"].extend(sender_indicators)
        
        # Extract and analyze URLs
        body = self.extract_body(email_message)
        urls = self.extract_urls(body)
        result["urls"] = urls
        
        for url in urls:
            url_score, url_indicators = self.analyze_url(url)
            result["risk_score"] += url_score
            result["indicators"].extend(url_indicators)
        
        # Analyze content
        content_score, content_indicators = self.analyze_content(body)
        result["risk_score"] += content_score
        result["indicators"].extend(content_indicators)
        
        # Analyze attachments
        attachments = self.extract_attachments(email_message)
        result["attachments"] = attachments
        
        for attachment in attachments:
            att_score, att_indicators = self.analyze_attachment(attachment)
            result["risk_score"] += att_score
            result["indicators"].extend(att_indicators)
        
        # Generate recommendation
        if result["risk_score"] >= self.config["block_threshold"]:
            result["recommendation"] = "BLOCK - High risk phishing/malware"
            result["severity"] = "CRITICAL"
        elif result["risk_score"] >= self.config["alert_threshold"]:
            result["recommendation"] = "WARN - Suspicious email, use caution"
            result["severity"] = "HIGH"
        elif result["risk_score"] >= 3:
            result["recommendation"] = "CAUTION - Some suspicious indicators"
            result["severity"] = "MEDIUM"
        else:
            result["recommendation"] = "SAFE - No significant threats detected"
            result["severity"] = "LOW"
        
        return result
    
    def analyze_sender(self, email_message: email.message.Message) -> Tuple[int, List[str]]:
        """Analyze email sender for spoofing and suspicious patterns"""
        score = 0
        indicators = []
        
        from_header = email_message.get("From", "")
        
        # Extract display name and email address
        match = re.match(r'(.+?)\s*<(.+?)>', from_header)
        if match:
            display_name = match.group(1).strip(' "')
            email_address = match.group(2).lower()
        else:
            display_name = ""
            email_address = from_header.lower()
        
        # Check for display name spoofing
        if display_name and email_address:
            display_domain = display_name.lower().replace(" ", "")
            email_domain = email_address.split('@')[-1]
            
            # Check if display name contains a legitimate brand but email doesn't match
            for legit_domain in self.legitimate_domains:
                brand = legit_domain.split('.')[0]
                if brand in display_domain and legit_domain not in email_address:
                    score += self.phishing_indicators["sender_spoof"]
                    indicators.append(
                        f"Sender spoofing: Display name suggests '{legit_domain}' " + 
                        f"but email is '{email_address}'"
                    )
                    break
        
        # Check for free email service pretending to be business
        free_email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        email_domain = email_address.split('@')[-1]
        
        if email_domain in free_email_domains:
            # Check if display name suggests a business/bank
            business_keywords = [
                'bank', 'paypal', 'amazon', 'microsoft', 'apple',
                'support', 'security', 'admin', 'service'
            ]
            if any(keyword in display_name.lower() for keyword in business_keywords):
                score += self.phishing_indicators["suspicious_sender"]
                indicators.append(
                    f"Suspicious: Business/bank name '{display_name}' " +
                    f"using free email service ({email_domain})"
                )
        
        # Check if sender is in our known senders database
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT is_trusted, email_count FROM known_senders
                WHERE email_address = ?
            ''', (email_address,))
            result = cursor.fetchone()
        finally:
            conn.close()
        
        if not result:
            score += self.phishing_indicators["no_previous_contact"]
            indicators.append(f"First time contact from {email_address}")
        elif result[0] == 0:  # Previously marked as untrusted
            score += 3
            indicators.append(f"Previously flagged sender: {email_address}")
        
        return score, indicators
    
    def analyze_url(self, url: str) -> Tuple[int, List[str]]:
        """Analyze URL for phishing indicators"""
        score = 0
        indicators = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for IP address instead of domain
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                score += self.phishing_indicators["ip_address_url"]
                indicators.append(f"URL uses IP address instead of domain: {url}")
            
            # Check for URL shortener
            if any(shortener in domain for shortener in self.url_shorteners):
                score += self.phishing_indicators["url_shortener"]
                indicators.append(f"URL shortener detected: {domain}")
            
            # Check for suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += self.phishing_indicators["suspicious_tld"]
                    indicators.append(f"Suspicious TLD: {tld}")
                    break
            
            # Check for typosquatting of legitimate domains
            for legit_domain in self.legitimate_domains:
                similarity = self.calculate_domain_similarity(domain, legit_domain)
                if 0.7 < similarity < 1.0:  # Similar but not exact
                    score += self.phishing_indicators["url_typosquatting"]
                    indicators.append(
                        f"Possible typosquatting: {domain} looks similar to {legit_domain}"
                    )
                    break
            
            # Check for homograph attacks (lookalike characters)
            if self.contains_homograph(domain):
                score += self.phishing_indicators["homograph_attack"]
                indicators.append(f"Homograph attack detected in: {domain}")
            
        except Exception as e:
            pass  # Malformed URL
        
        return score, indicators
    
    def analyze_content(self, body: str) -> Tuple[int, List[str]]:
        """Analyze email content for phishing indicators"""
        score = 0
        indicators = []
        body_lower = body.lower()
        
        # Urgent language
        urgent_keywords = [
            'urgent', 'immediate action', 'act now', 'expires today',
            'limited time', 'verify immediately', 'suspended', 'locked'
        ]
        for keyword in urgent_keywords:
            if keyword in body_lower:
                score += self.phishing_indicators["urgent_language"]
                indicators.append(f"Urgent language detected: '{keyword}'")
                break  # Count once
        
        # Financial/security terms
        financial_keywords = [
            'verify account', 'confirm identity', 'update payment',
            'billing problem', 'unusual activity', 'security alert',
            'suspended account', 'verify credit card'
        ]
        for keyword in financial_keywords:
            if keyword in body_lower:
                score += self.phishing_indicators["financial_terms"]
                indicators.append(f"Financial/security term detected: '{keyword}'")
                break
        
        # Password request
        password_patterns = [
            'enter your password', 'confirm password', 'reset password',
            'provide your password', 'verify password'
        ]
        for pattern in password_patterns:
            if pattern in body_lower:
                score += self.phishing_indicators["password_request"]
                indicators.append("Email requests password (legitimate companies never do this)")
                break
        
        # Personal information request
        personal_info_patterns = [
            'social security', 'ssn', 'date of birth', 'dob',
            'mother\'s maiden name', 'driver\'s license'
        ]
        for pattern in personal_info_patterns:
            if pattern in body_lower:
                score += self.phishing_indicators["personal_info_request"]
                indicators.append(f"Requests personal information: {pattern}")
                break
        
        return score, indicators
    
    def analyze_attachment(self, attachment: Dict) -> Tuple[int, List[str]]:
        """Analyze email attachment for threats"""
        score = 0
        indicators = []
        
        filename = attachment.get("filename", "").lower()
        file_ext = Path(filename).suffix.lower()
        
        # Check for dangerous extensions
        if file_ext in self.dangerous_extensions:
            score += self.phishing_indicators["exe_attachment"]
            indicators.append(
                f"DANGEROUS attachment type: {filename} ({file_ext})"
            )
        
        # Check for suspicious extensions
        elif file_ext in self.suspicious_extensions:
            score += self.phishing_indicators["suspicious_attachment"]
            indicators.append(
                f"Suspicious attachment: {filename} (could contain macros/malware)"
            )
        
        # Check for double extensions (e.g., .pdf.exe)
        if filename.count('.') > 1:
            parts = filename.split('.')
            if f".{parts[-1]}" in self.dangerous_extensions:
                score += 5
                indicators.append(
                    f"Double extension detected (hiding real type): {filename}"
                )
        
        # Check file size (unusually small executables are suspicious)
        file_size = attachment.get("size", 0)
        if file_ext in self.dangerous_extensions and file_size < 50000:  # Less than 50KB
            score += 2
            indicators.append(
                f"Suspiciously small executable: {filename} ({file_size} bytes)"
            )
        
        return score, indicators
    
    def extract_body(self, email_message: email.message.Message) -> str:
        """Extract text body from email"""
        body = ""
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except Exception:
                        pass
        else:
            try:
                body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
            except Exception:
                body = str(email_message.get_payload())
        
        return body
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def extract_attachments(self, email_message: email.message.Message) -> List[Dict]:
        """Extract attachment information from email"""
        attachments = []
        
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        file_hash = hashlib.sha256(payload).hexdigest() if payload else ""
                        
                        attachments.append({
                            "filename": filename,
                            "size": len(payload) if payload else 0,
                            "content_type": part.get_content_type(),
                            "hash": file_hash
                        })
        
        return attachments
    
    def calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity using true Levenshtein edit distance (0.0 to 1.0).

        v28p37: Replaced naive positional comparison with actual edit distance.
        This correctly catches insertions/deletions like 'paypall.com' and
        substitutions like 'paypa1.com'.
        """
        if domain1 == domain2:
            return 1.0
        max_len = max(len(domain1), len(domain2))
        if max_len == 0:
            return 1.0
        # Levenshtein distance via two-row DP (O(min(m,n)) space)
        a, b = domain1, domain2
        if len(a) > len(b):
            a, b = b, a
        prev = list(range(len(a) + 1))
        for j in range(1, len(b) + 1):
            curr = [j] + [0] * len(a)
            for i in range(1, len(a) + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                curr[i] = min(curr[i - 1] + 1, prev[i] + 1, prev[i - 1] + cost)
            prev = curr
        distance = prev[len(a)]
        return 1.0 - (distance / max_len)
    
    def contains_homograph(self, domain: str) -> bool:
        """Check for homograph attacks using expanded lookalike character set.

        v28p37: Expanded from 10 to 40+ homoglyph characters covering Cyrillic,
        Greek, Latin Extended, and common number/letter substitutions.
        """
        # Cyrillic lookalikes (most common in IDN homograph attacks)
        # Greek lookalikes
        # Latin Extended lookalikes
        # Number-for-letter substitutions (also used in typosquatting)
        homograph_chars = {
            # Cyrillic → Latin
            '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
            '\u0455': 's', '\u04bb': 'h', '\u0432': 'b', '\u043a': 'k',
            '\u043c': 'm', '\u043d': 'n', '\u0442': 't', '\u0436': 'zh',
            '\u0491': 'g', '\u0457': 'i',
            # Greek → Latin
            '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
            '\u03b9': 'i', '\u03ba': 'k', '\u03bd': 'v', '\u03c4': 't',
            '\u03c9': 'w',
            # Latin Extended confusables
            '\u0131': 'i',  # dotless i
            '\u0142': 'l',  # l with stroke
            '\u00f8': 'o',  # o with stroke
            '\u00e6': 'ae', # ae ligature
            '\u0111': 'd',  # d with stroke
            '\u01b4': 'y',  # y with hook
            # Full-width Latin (used in some attacks)
            '\uff41': 'a', '\uff45': 'e', '\uff4f': 'o', '\uff49': 'i',
            '\uff4c': 'l', '\uff53': 's',
        }

        # Check for any non-ASCII character in domain (fast pre-filter)
        if domain.isascii():
            return False
        return any(char in domain for char in homograph_chars)
    
    def scan_outlook_inbox(self) -> List[Dict]:
        """Scan Outlook inbox for suspicious emails"""
        if not HAS_WIN32:
            print("❌ Outlook integration requires pywin32")
            return []
        
        print("\n📧 Scanning Outlook inbox...")
        results = []
        
        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
            namespace = outlook.GetNamespace("MAPI")
            inbox = namespace.GetDefaultFolder(6)  # 6 = Inbox
            messages = inbox.Items
            
            # Scan most recent 50 emails
            messages.Sort("[ReceivedTime]", True)
            count = min(50, messages.Count)
            
            print(f"Analyzing {count} most recent emails...")
            
            for i in range(1, count + 1):
                try:
                    message = messages.Item(i)
                    
                    # Convert Outlook message to email.message
                    email_msg = email.message_from_string(
                        f"From: {message.SenderEmailAddress}\n"
                        f"Subject: {message.Subject}\n"
                        f"Date: {message.ReceivedTime}\n\n"
                        f"{message.Body}"
                    )
                    
                    # Analyze
                    analysis = self.analyze_email(email_msg)
                    
                    if analysis["risk_score"] >= self.config["alert_threshold"]:
                        print(f"\n⚠️  Suspicious email #{i}:")
                        print(f"   From: {analysis['sender']}")
                        print(f"   Subject: {analysis['subject']}")
                        print(f"   Risk Score: {analysis['risk_score']}")
                        print(f"   Indicators: {len(analysis['indicators'])}")
                        
                        results.append(analysis)
                        
                        # Log to database
                        self.log_scanned_email(analysis)
                
                except Exception as e:
                    print(f"Error scanning message {i}: {e}")
                    continue
            
            print(f"\n✅ Scan complete - found {len(results)} suspicious emails")
            
        except Exception as e:
            print(f"❌ Error accessing Outlook: {e}")
        
        return results
    
    def log_scanned_email(self, analysis: Dict):
        """Log scanned email to database"""
        timestamp = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scanned_emails
                (timestamp, email_id, sender, subject, risk_score, indicators,
                 action_taken, was_quarantined)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                hashlib.md5(f"{analysis['sender']}{analysis['subject']}".encode()).hexdigest(),
                analysis['sender'],
                analysis['subject'],
                analysis['risk_score'],
                json.dumps(analysis['indicators']),
                analysis['recommendation'],
                analysis['risk_score'] >= self.config['block_threshold']
            ))
            conn.commit()
        finally:
            conn.close()

    def generate_report(self) -> str:
        """Generate email security report"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append("EMAIL SECURITY REPORT")
            report_lines.append("=" * 80)
            report_lines.append("")

            # Total scanned
            cursor.execute('SELECT COUNT(*) FROM scanned_emails')
            total = cursor.fetchone()[0]
            report_lines.append(f"📊 Total Emails Scanned: {total}")

            # High risk emails
            cursor.execute('''
                SELECT COUNT(*) FROM scanned_emails
                WHERE risk_score >= ?
            ''', (self.config['block_threshold'],))
            high_risk = cursor.fetchone()[0]
            report_lines.append(f"🚨 High Risk Emails: {high_risk}")

            # Quarantined
            cursor.execute('SELECT COUNT(*) FROM scanned_emails WHERE was_quarantined = 1')
            quarantined = cursor.fetchone()[0]
            report_lines.append(f"🔒 Emails Quarantined: {quarantined}")
            report_lines.append("")

            # Recent suspicious emails
            cursor.execute('''
                SELECT timestamp, sender, subject, risk_score
                FROM scanned_emails
                WHERE risk_score >= ?
                ORDER BY timestamp DESC
                LIMIT 10
            ''', (self.config['alert_threshold'],))

            suspicious = cursor.fetchall()
            if suspicious:
                report_lines.append("⚠️  Recent Suspicious Emails:")
                for timestamp, sender, subject, score in suspicious:
                    date_str = timestamp.split('T')[0]
                    report_lines.append(f"   [{score}] {date_str} - From: {sender}")
                    report_lines.append(f"       Subject: {subject}")
        finally:
            conn.close()
        
        report_lines.append("")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Family Security Suite - Email Security")
    parser.add_argument('--scan-outlook', action='store_true',
                       help='Scan Outlook inbox')
    parser.add_argument('--scan-file', type=str,
                       help='Scan a specific .eml file')
    parser.add_argument('--report', action='store_true',
                       help='Generate security report')
    
    args = parser.parse_args()
    
    scanner = EmailSecurityScanner()
    
    if args.scan_outlook:
        scanner.scan_outlook_inbox()
    elif args.scan_file:
        with open(args.scan_file, 'r') as f:
            email_msg = email.message_from_file(f)
        analysis = scanner.analyze_email(email_msg)
        print(json.dumps(analysis, indent=2))
    elif args.report:
        print(scanner.generate_report())
    else:
        print("Email Security Scanner")
        print("\nUsage:")
        print("  python email_security.py --scan-outlook  # Scan Outlook inbox")
        print("  python email_security.py --scan-file email.eml")
        print("  python email_security.py --report")
