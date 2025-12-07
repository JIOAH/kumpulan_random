#!/usr/bin/env python3
"""
WebRecon Pro - Advanced OSINT Web Reconnaissance Tool
Fixed LinkedIn URL Detection with Consistent Formatting
Author: D4rk_Intel
Project: OSINT Reconnaissance Tool
"""

import os
import re
import json
import argparse
import requests
import time
import urllib.parse
import tldextract
import socket
import threading
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Suppress ALL warnings
import warnings
warnings.filterwarnings("ignore")

class ColorOutput:
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def finding(msg):
        print(f"{Fore.MAGENTA}[FINDING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def whois(msg):
        print(f"{Fore.BLUE}[WHOIS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def dns(msg):
        print(f"{Fore.CYAN}[DNS]{Style.RESET_ALL} {msg}")

class Config:
    def __init__(self):
        # AWS Configuration for FireProx
        self.AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
        
        # Request Configuration
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.TIMEOUT = 30
        self.MAX_RETRIES = 3
        
        # Crawler Configuration
        self.MAX_PAGES = 100
        self.MAX_DEPTH = 2
        self.CRAWL_DELAY = 1
        
        # Output Configuration
        self.OUTPUT_DIR = "webrecon_output"
        
        # Proxy Configuration
        self.HTTP_PROXY = os.getenv('HTTP_PROXY')
        self.SOCKS_PROXY = os.getenv('SOCKS_PROXY')

class PatternMatcher:
    # Email patterns
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Cloud storage patterns
    AWS_S3_PATTERN = r'https?://[a-zA-Z0-9.-]*\.?s3[.-]([a-z0-9-]+)?\.amazonaws\.com'
    AZURE_BLOB_PATTERN = r'https?://[a-zA-Z0-9.-]*\.blob\.core\.windows\.net'
    GCP_STORAGE_PATTERN = r'https?://storage\.cloud\.google\.com/[^\s"\']+'
    
    # Social media patterns - FIXED LINKEDIN PATTERNS
    SOCIAL_MEDIA_PATTERNS = {
        'facebook': r'https?://(?:www\.)?facebook\.com/[^\s"\']+',
        'twitter': r'https?://(?:www\.)?twitter\.com/[^\s"\']+',
        'linkedin': r'https?://(?:www\.)?linkedin\.com/(?:company/[^\s"\']+|in/[^\s"\']+|showcase/[^\s"\']+)',
        'instagram': r'https?://(?:www\.)?instagram\.com/[^\s"\']+',
        'youtube': r'https?://(?:www\.)?youtube\.com/[^\s"\']+',
        'github': r'https?://(?:www\.)?github\.com/[^\s"\']+'
    }
    
    # File patterns
    FILE_PATTERNS = {
        'pdf': r'[^"\']+\.pdf(?:\?[^"\']*)?',
        'doc': r'[^"\']+\.(?:doc|docx)(?:\?[^"\']*)?',
        'xls': r'[^"\']+\.(?:xls|xlsx)(?:\?[^"\']*)?',
        'ppt': r'[^"\']+\.(?:ppt|pptx)(?:\?[^"\']*)?',
        'txt': r'[^"\']+\.txt(?:\?[^"\']*)?',
        'csv': r'[^"\']+\.csv(?:\?[^"\']*)?',
        'zip': r'[^"\']+\.(?:zip|rar|7z)(?:\?[^"\']*)?',
        'config': r'[^"\']+\.(?:config|conf|ini)(?:\?[^"\']*)?',
        'sql': r'[^"\']+\.sql(?:\?[^"\']*)?',
        'log': r'[^"\']+\.log(?:\?[^"\']*)?'
    }

class URLUtils:
    @staticmethod
    def is_valid_url(url):
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def get_domain(url):
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    @staticmethod
    def get_subdomain(url):
        extracted = tldextract.extract(url)
        return extracted.subdomain
    
    @staticmethod
    def normalize_url(url):
        """Normalize URL for consistent comparison"""
        parsed = urllib.parse.urlparse(url)
        normalized = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path,
            '',  # params
            '',  # query
            ''   # fragment
        ))
        return normalized.rstrip('/')
    
    @staticmethod
    def should_skip_url(url):
        """Check if URL should be skipped (email protection, etc.)"""
        skip_patterns = [
            r'cdn-cgi/l/email-protection',  # Cloudflare email protection
            r'mailto:',  # Mailto links
            r'tel:',  # Telephone links
            r'javascript:',  # JavaScript links
            r'#',  # Anchor links
            r'hubspot\.com',  # HubSpot URLs that cause DNS issues
            r'linkedin\.com/psettings',  # LinkedIn settings
            r'facebook\.com/sharer',  # Facebook share links
            r'twitter\.com/intent',  # Twitter intent links
            r'facebook\.com/.*[0-9]{15,}',  # Facebook numeric IDs that cause 400 errors
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in skip_patterns)

class DataExtractor:
    def __init__(self, base_url):
        self.base_url = base_url
        self.base_domain = URLUtils.get_domain(base_url)
        self.pattern_matcher = PatternMatcher()
    
    def extract_emails(self, text):
        emails = set(re.findall(self.pattern_matcher.EMAIL_PATTERN, text, re.IGNORECASE))
        
        # Enhanced filtering for false positives
        filtered_emails = []
        for email in emails:
            email_lower = email.lower()
            
            # Skip common placeholder emails and false positives
            false_positive_domains = [
                'example.com', 'domain.com', 'email.com', 'test.com',
                'yourdomain.com', 'sentry.io', 'wixpress.com', 'sentry-next.wixpress.com',
                'localhost', '127.0.0.1', 'your-email.com', 'company.com',
                'placeholder.com', 'fake.com', 'test.org', 'example.org'
            ]
            
            # Skip emails with common false positive patterns
            false_positive_patterns = [
                r'noreply@', r'no-reply@', r'support@.*\.test', r'info@.*\.local',
                r'admin@.*\.local', r'root@', r'postmaster@', r'webmaster@',
                r'^[a-f0-9]{32}@',  # Filter hex hash emails like sentry IDs
                r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@',  # UUID emails
            ]
            
            # Check if email should be filtered
            should_filter = (
                any(domain in email_lower for domain in false_positive_domains) or
                any(re.search(pattern, email_lower) for pattern in false_positive_patterns) or
                len(email) < 6 or  # Too short
                '..' in email or  # Double dots
                email.count('@') != 1 or  # Multiple @ symbols
                email.startswith('.') or email.endswith('.')  # Starts or ends with dot
            )
            
            # Additional validation for real emails
            if not should_filter:
                # Check if it looks like a real person's email (not system/automated)
                if self._is_likely_real_email(email):
                    filtered_emails.append(email)
        
        # Remove duplicates and display unique emails only
        unique_emails = list(set(filtered_emails))
        for email in unique_emails:
            ColorOutput.finding(f"Valid email found: {email}")
        
        return unique_emails
    
    def _is_likely_real_email(self, email):
        """Check if email appears to be from a real person/organization"""
        email_lower = email.lower()
        
        # Common real email patterns
        real_patterns = [
            r'^[a-zA-Z]+\.[a-zA-Z]+@',  # first.last@domain
            r'^[a-zA-Z]+@',              # first@domain
            r'^[a-zA-Z][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # general valid email
        ]
        
        # Common automated/system email patterns to exclude
        system_patterns = [
            r'^[a-f0-9]+@',              # hex hashes
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@',  # UUIDs
            r'^[0-9]+@',                 # numeric-only usernames
            r'^[a-z0-9]{32}@',           # 32-character hashes
            r'@sentry\.',                # Sentry-related
            r'@.*\.sentry\.',            # Any subdomain of sentry
            r'@.*\.local$',              # Local domains
            r'@.*\.test$',               # Test domains
        ]
        
        # Must match real patterns
        if not any(re.search(pattern, email_lower) for pattern in real_patterns):
            return False
        
        # Must NOT match system patterns
        if any(re.search(pattern, email_lower) for pattern in system_patterns):
            return False
        
        return True
    
    def extract_social_media(self, text):
        social_media = {}
        
        # IMPROVED patterns to avoid false positives - FIXED LINKEDIN
        improved_patterns = {
            'facebook': [
                r'https?://(?:www\.)?facebook\.com/(?!sharer\.php)(?![^/]*\/sharer\.php)(?![^/]*\/share\.php)([a-zA-Z0-9\.\-]+)',
                r'https?://(?:www\.)?fb\.com/([a-zA-Z0-9\.\-]+)'
            ],
            'twitter': [
                r'https?://(?:www\.)?twitter\.com/(?!share|intent/tweet)([a-zA-Z0-9_]+)',
                r'https?://(?:www\.)?x\.com/([a-zA-Z0-9_]+)'
            ],
            'linkedin': [
                # FIXED: Proper LinkedIn patterns that actually work
                r'https?://(?:www\.)?linkedin\.com/company/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/showcase/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/school/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/pages/([a-zA-Z0-9\-]+)/?'
            ],
            'instagram': [
                r'https?://(?:www\.)?instagram\.com/([a-zA-Z0-9\._]+)'
            ],
            'youtube': [
                r'https?://(?:www\.)?youtube\.com/(?!redirect|embed)(?:c/|channel/|user/|@)?([a-zA-Z0-9\-_]+)',
                r'https?://(?:www\.)?youtu\.be/([a-zA-Z0-9\-_]+)'
            ],
            'github': [
                r'https?://(?:www\.)?github\.com/([a-zA-Z0-9\-_]+)'
            ]
        }
        
        for platform, patterns in improved_patterns.items():
            matches = set()
            for pattern in patterns:
                found = re.findall(pattern, text, re.IGNORECASE)
                for match in found:
                    # Reconstruct clean URL - FIXED FOR LINKEDIN
                    if platform == 'facebook':
                        clean_url = f"https://www.facebook.com/{match}"
                    elif platform == 'twitter':
                        clean_url = f"https://www.twitter.com/{match}"
                    elif platform == 'linkedin':
                        # Determine LinkedIn URL type based on pattern
                        if 'company' in pattern:
                            clean_url = f"https://www.linkedin.com/company/{match}"
                        elif 'in' in pattern:
                            clean_url = f"https://www.linkedin.com/in/{match}"
                        elif 'showcase' in pattern:
                            clean_url = f"https://www.linkedin.com/showcase/{match}"
                        elif 'school' in pattern:
                            clean_url = f"https://www.linkedin.com/school/{match}"
                        elif 'pages' in pattern:
                            clean_url = f"https://www.linkedin.com/pages/{match}"
                        else:
                            clean_url = f"https://www.linkedin.com/company/{match}"
                    elif platform == 'instagram':
                        clean_url = f"https://www.instagram.com/{match}"
                    elif platform == 'youtube':
                        clean_url = f"https://www.youtube.com/{match}"
                    elif platform == 'github':
                        clean_url = f"https://www.github.com/{match}"
                    
                    # Additional filtering
                    if self._is_valid_social_url(clean_url):
                        matches.add(clean_url)
            
            if matches:
                social_media[platform] = list(matches)
        
        return social_media
    
    def _is_valid_social_url(self, url):
        """Filter out social media false positives"""
        false_positive_indicators = [
            'sharer.php', 'share.php', 'share', 'intent/tweet', 
            'redirect', 'embed', 'widgets', 'plugins', 'button',
            'like.php', 'follow.php', 'comment', 'dialog', 'popup'
        ]
        
        url_lower = url.lower()
        
        # Skip if it contains false positive indicators
        if any(indicator in url_lower for indicator in false_positive_indicators):
            return False
        
        # Skip YouTube redirect URLs
        if 'youtube.com/redirect' in url_lower:
            return False
        
        # Skip URLs with numeric IDs (Facebook pages with long numbers)
        if re.search(r'facebook\.com/\d{10,}', url_lower):
            return False
        
        # Skip invalid LinkedIn patterns (like "sans-institute" without proper path)
        if 'linkedin.com' in url_lower:
            # Must have proper LinkedIn path structure
            linkedin_patterns = [
                r'linkedin\.com/company/[a-zA-Z0-9\-]+',
                r'linkedin\.com/in/[a-zA-Z0-9\-]+', 
                r'linkedin\.com/showcase/[a-zA-Z0-9\-]+',
                r'linkedin\.com/school/[a-zA-Z0-9\-]+',
                r'linkedin\.com/pages/[a-zA-Z0-9\-]+'
            ]
            if not any(re.search(pattern, url_lower) for pattern in linkedin_patterns):
                return False
        
        return True
    
    def extract_cloud_storage(self, text):
        cloud_links = {
            'aws_s3': re.findall(self.pattern_matcher.AWS_S3_PATTERN, text, re.IGNORECASE),
            'azure_blob': re.findall(self.pattern_matcher.AZURE_BLOB_PATTERN, text, re.IGNORECASE),
            'gcp_storage': re.findall(self.pattern_matcher.GCP_STORAGE_PATTERN, text, re.IGNORECASE)
        }
        return {k: list(set(v)) for k, v in cloud_links.items() if v}
    
    def extract_subdomains(self, urls):
        subdomains = set()
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                extracted = tldextract.extract(parsed.netloc)
                if extracted.subdomain and extracted.domain and extracted.suffix:
                    full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                    if extracted.domain + '.' + extracted.suffix == self.base_domain:
                        subdomains.add(full_domain)
            except:
                continue
        return list(subdomains)
    
    def extract_files(self, urls):
        files = {}
        for file_type, pattern in self.pattern_matcher.FILE_PATTERNS.items():
            matches = []
            for url in urls:
                if re.search(pattern, url, re.IGNORECASE):
                    matches.append(url)
            if matches:
                files[file_type] = list(set(matches))
        return files
    
    def extract_html_comments(self, html_content):
        comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        # Filter out common false positives and empty comments
        filtered_comments = []
        for comment in comments:
            clean_comment = comment.strip()
            if (clean_comment and 
                len(clean_comment) > 5 and  # Skip very short comments
                not clean_comment.startswith('[if') and  # Skip conditional comments
                'google' not in clean_comment.lower() and  # Skip Google analytics
                'facebook' not in clean_comment.lower()):  # Skip Facebook pixel
                filtered_comments.append(clean_comment)
        return filtered_comments
    
    def extract_js_sources(self, soup):
        js_sources = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urllib.parse.urljoin(self.base_url, src)
                if URLUtils.is_valid_url(full_url):
                    js_sources.append(full_url)
        return list(set(js_sources))
    
    def extract_marketing_tags(self, soup, html_content):
        tags = {}
        
        # FIXED: Better Google Analytics patterns to avoid false positives
        ga_patterns = [
            r'UA-\d{4,10}-\d{1,4}',  # Universal Analytics
            r'GTM-[A-Z0-9]{4,10}',    # Google Tag Manager  
            r'G-[A-Z0-9]{8,10}',      # Google Analytics 4 (proper format)
        ]
        
        for pattern in ga_patterns:
            matches = re.findall(pattern, html_content)
            valid_matches = [match for match in matches if len(match) > 6]  # Filter out short false positives
            if valid_matches:
                tags['google_analytics'] = list(set(valid_matches))
                for match in valid_matches:
                    ColorOutput.finding(f"Marketing tag (google_analytics): {match}")
        
        # Google Tag Manager
        if soup.find('script', string=re.compile('googletagmanager', re.I)):
            tags['google_tag_manager'] = True
            ColorOutput.finding("Marketing tag (google_tag_manager): detected")
        
        # Facebook Pixel
        if re.search(r'facebook\.com\/tr\/?', html_content, re.I):
            tags['facebook_pixel'] = True
            ColorOutput.finding("Marketing tag (facebook_pixel): detected")
        
        # Hotjar
        if re.search(r'hotjar', html_content, re.I):
            tags['hotjar'] = True
            ColorOutput.finding("Marketing tag (hotjar): detected")
        
        return tags
    
    def extract_login_pages(self, urls, soup):
        login_indicators = [
            'login', 'signin', 'auth', 'authenticate', 'logon', 'signon',
            'password', 'credential', 'session', 'oauth', 'sso'
        ]
        
        login_urls = set()
        
        # Check URLs
        for url in urls:
            url_lower = url.lower()
            if any(indicator in url_lower for indicator in login_indicators):
                login_urls.add(url)
        
        # Check form actions
        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            if any(indicator in action for indicator in login_indicators):
                full_url = urllib.parse.urljoin(self.base_url, form.get('action', ''))
                if URLUtils.is_valid_url(full_url):
                    login_urls.add(full_url)
        
        return list(login_urls)
    
    def extract_interesting_findings(self, soup, response_text, url):
        interesting = {}
        
        # Frame ancestors
        iframes = soup.find_all('iframe')
        if iframes:
            interesting['iframes'] = [urllib.parse.urljoin(url, iframe.get('src')) 
                                    for iframe in iframes if iframe.get('src')]
        
        # JSON content detection
        try:
            json.loads(response_text)
            interesting['json_content'] = url
        except:
            pass
        
        return interesting

# DNS Information Gathering
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class DNSRecon:
    def __init__(self):
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            # Set shorter timeouts to avoid hanging
            self.resolver.timeout = 5
            self.resolver.lifetime = 5
        else:
            self.resolver = None
    
    def gather_dns_info(self, domain):
        dns_info = {}
        
        if not self.resolver:
            return dns_info
            
        try:
            # A records
            a_records = self.resolver.resolve(domain, 'A')
            dns_info['a_records'] = [str(record) for record in a_records]
            
            # MX records
            mx_records = self.resolver.resolve(domain, 'MX')
            dns_info['mx_records'] = [str(record.exchange) for record in mx_records]
            
            # TXT records
            txt_records = self.resolver.resolve(domain, 'TXT')
            dns_info['txt_records'] = [str(record) for record in txt_records]
            
            # NS records
            ns_records = self.resolver.resolve(domain, 'NS')
            dns_info['ns_recards'] = [str(record) for record in ns_records]
            
            # CNAME records
            try:
                cname_records = self.resolver.resolve(domain, 'CNAME')
                dns_info['cname_records'] = [str(record) for record in cname_records]
            except:
                dns_info['cname_records'] = []
                
        except Exception:
            pass  # Silent fail for DNS
        
        return dns_info

# DNSDumpster Automation
class DNSDumpsterAutomation:
    def __init__(self):
        self.base_url = "https://dnsdumpster.com"
    
    def open_in_browser(self, domain):
        """Open DNSDumpster analysis in browser with domain pre-filled"""
        try:
            import webbrowser
            
            # Direct URL with domain parameter for automatic lookup
            dnsdumpster_url = f"https://dnsdumpster.com/?q={domain}"
            ColorOutput.info(f"DNSDumpster: {dnsdumpster_url}")
            
            # Auto-open without prompt - will automatically show results for the domain
            webbrowser.open(dnsdumpster_url)
            ColorOutput.success("Opened DNSDumpster in browser - domain lookup initiated automatically")
            
            # Display information about DNSDumpster
            ColorOutput.dns("DNSDumpster provides comprehensive DNS reconnaissance including:")
            ColorOutput.dns("  • Domain IP addresses and hosting information")
            ColorOutput.dns("  • Subdomain enumeration")
            ColorOutput.dns("  • DNS record analysis (A, MX, TXT, NS, CNAME)")
            ColorOutput.dns("  • Network infrastructure mapping")
            
            # Get and display basic domain IP information
            ip_info = self.get_domain_ip_info(domain)
            if ip_info.get('primary_ip'):
                ColorOutput.finding(f"Domain IP Address: {ip_info['primary_ip']}")
            if ip_info.get('reverse_dns') and ip_info['reverse_dns'] != "Not available":
                ColorOutput.finding(f"Reverse DNS: {ip_info['reverse_dns']}")
                
        except ImportError:
            ColorOutput.info(f"DNSDumpster URL: https://dnsdumpster.com/?q={domain}")
    
    def get_domain_ip_info(self, domain):
        """Get domain IP information (simplified version)"""
        ip_info = {}
        
        try:
            # Simple DNS resolution for primary domain IP
            ip_address = socket.gethostbyname(domain)
            ip_info['primary_ip'] = ip_address
            
            # Additional IP information
            try:
                hostname = socket.gethostbyaddr(ip_address)
                ip_info['reverse_dns'] = hostname[0]
            except:
                ip_info['reverse_dns'] = "Not available"
            
        except Exception as e:
            ip_info['error'] = f"Could not resolve domain IP: {e}"
        
        return ip_info

# WHOIS Lookup - FIXED VERSION
try:
    import whois
    import whois.parser
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

class WHOISLookup:
    def __init__(self):
        self.last_error = None
    
    def _safe_getattr(self, obj, attr_name, default='Unknown'):
        """Safely get attribute from WHOIS object"""
        try:
            value = getattr(obj, attr_name, default)
            if value is None:
                return default
            if isinstance(value, list) and not value:
                return default
            return value
        except:
            return default
    
    def _safe_date_getattr(self, obj, attr_name):
        """Safely extract date from WHOIS object"""
        try:
            value = getattr(obj, attr_name, None)
            if not value:
                return 'Unknown'
            if isinstance(value, list):
                if value:
                    return str(value[0])
                return 'Unknown'
            return str(value)
        except:
            return 'Unknown'
    
    def _safe_list_getattr(self, obj, attr_name):
        """Safely extract list from WHOIS object"""
        try:
            value = getattr(obj, attr_name, [])
            if not value:
                return []
            if isinstance(value, list):
                return [str(item) for item in value if item]
            return [str(value)]
        except:
            return []
    
    def get_whois_info(self, domain):
        """WHOIS lookup with comprehensive error handling - FIXED VERSION"""
        whois_info = {}
        
        if not WHOIS_AVAILABLE:
            return whois_info
            
        try:
            ColorOutput.info(f"Performing WHOIS lookup for: {domain}")
            
            # Set timeout to prevent hanging
            import socket
            socket.setdefaulttimeout(15)
            
            # Perform WHOIS lookup with enhanced error handling
            try:
                w = whois.whois(domain)
            except Exception as e:
                # Handle specific WHOIS errors silently
                return whois_info
            
            # Check if we got valid data
            if not w or not hasattr(w, 'domain_name'):
                return whois_info
            
            # Extract comprehensive WHOIS data
            whois_data = {
                'registrar': self._safe_getattr(w, 'registrar'),
                'creation_date': self._safe_date_getattr(w, 'creation_date'),
                'expiration_date': self._safe_date_getattr(w, 'expiration_date'),
                'updated_date': self._safe_date_getattr(w, 'updated_date'),
                'name_servers': self._safe_list_getattr(w, 'name_servers'),
                'emails': self._safe_list_getattr(w, 'emails'),
                'org': self._safe_getattr(w, 'org'),
                'country': self._safe_getattr(w, 'country'),
                'state': self._safe_getattr(w, 'state'),
                'city': self._safe_getattr(w, 'city'),
                'address': self._safe_getattr(w, 'address'),
                'zipcode': self._safe_getattr(w, 'zipcode'),
                'name': self._safe_getattr(w, 'name'),
                'dnssec': self._safe_getattr(w, 'dnssec'),
                'status': self._safe_list_getattr(w, 'status')
            }
            
            # Filter out empty values for cleaner output
            whois_info = {k: v for k, v in whois_data.items() if v and v != 'Unknown' and v != []}
            
            # Display results
            if whois_info:
                ColorOutput.success(f"WHOIS lookup completed for {domain}")
                self._display_whois_results(domain, whois_info)
                
        except Exception as e:
            # Silent fail for all errors
            pass
        
        # Reset socket timeout
        import socket
        socket.setdefaulttimeout(None)
        
        return whois_info
    
    def _display_whois_results(self, domain, whois_info):
        """Display WHOIS results in a formatted way"""
        ColorOutput.whois("=" * 60)
        ColorOutput.whois(f"WHOIS RESULTS FOR: {domain.upper()}")
        ColorOutput.whois("=" * 60)
        
        # Display key information in organized sections
        
        # Registrar Information
        if whois_info.get('registrar'):
            ColorOutput.whois(f"Registrar: {whois_info['registrar']}")
        
        # Dates Section
        date_info = []
        if whois_info.get('creation_date'):
            date_info.append(f"Created: {whois_info['creation_date']}")
        if whois_info.get('expiration_date'):
            date_info.append(f"Expires: {whois_info['expiration_date']}")
        if whois_info.get('updated_date'):
            date_info.append(f"Updated: {whois_info['updated_date']}")
        
        if date_info:
            ColorOutput.whois("Domain Dates:")
            for date in date_info:
                ColorOutput.whois(f"   {date}")
        
        # Organization Information
        org_info = []
        if whois_info.get('org'):
            org_info.append(f"Organization: {whois_info['org']}")
        if whois_info.get('name'):
            org_info.append(f"Registrant: {whois_info['name']}")
        
        if org_info:
            ColorOutput.whois("Organization:")
            for info in org_info:
                ColorOutput.whois(f"   {info}")
        
        # Location Information
        location_info = []
        if whois_info.get('country'):
            location_info.append(f"Country: {whois_info['country']}")
        if whois_info.get('state'):
            location_info.append(f"State: {whois_info['state']}")
        if whois_info.get('city'):
            location_info.append(f"City: {whois_info['city']}")
        
        if location_info:
            ColorOutput.whois("Location:")
            for loc in location_info:
                ColorOutput.whois(f"   {loc}")
        
        # Name Servers
        if whois_info.get('name_servers'):
            ColorOutput.whois("Name Servers:")
            for ns in whois_info['name_servers'][:5]:  # Show first 5
                ColorOutput.whois(f"   {ns}")
        
        # Contact Emails
        if whois_info.get('emails'):
            ColorOutput.whois("Contact Emails:")
            for email in whois_info['emails'][:3]:  # Show first 3
                ColorOutput.whois(f"   {email}")
        
        # Domain Status
        if whois_info.get('status'):
            ColorOutput.whois("Domain Status:")
            for status in whois_info['status'][:3]:  # Show first 3 statuses
                ColorOutput.whois(f"   {status}")
        
        # DNSSEC
        if whois_info.get('dnssec'):
            ColorOutput.whois(f"DNSSEC: {whois_info['dnssec']}")
        
        ColorOutput.whois("=" * 60)
    
    def open_in_browser(self, domain):
        """Open WHOIS lookup in browser - this is the reliable method"""
        try:
            import webbrowser
            
            # Multiple WHOIS lookup services - these are more reliable
            whois_services = [
                f"https://whois.domaintools.com/{domain}",
                f"https://whois.icann.org/en/lookup?name={domain}",
                f"https://www.whois.com/whois/{domain}",
                f"https://who.is/whois/{domain}"
            ]
            
            ColorOutput.info("Opening WHOIS lookup in browser services...")
            ColorOutput.info("Browser-based WHOIS lookups are more reliable than API-based queries")
            
            for service_url in whois_services[:2]:  # Open first 2 services
                webbrowser.open(service_url)
                time.sleep(0.5)
            
            ColorOutput.success("WHOIS services opened in browser")
            
        except ImportError:
            ColorOutput.info("WHOIS Service URLs:")
            ColorOutput.info(f"   https://whois.domaintools.com/{domain}")
            ColorOutput.info(f"   https://whois.icann.org/en/lookup?name={domain}")

# Wayback Machine Integration
class WaybackMachine:
    def get_historical_data(self, domain):
        historical_data = {}
        
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey&limit=10"
            response = requests.get(wayback_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # First row is headers
                    historical_data['total_snapshots'] = len(data) - 1
                    historical_data['oldest_snapshot'] = data[1][1] if len(data) > 1 else None
                    historical_data['newest_snapshot'] = data[-1][1] if len(data) > 1 else None
                    historical_data['sample_urls'] = [entry[2] for entry in data[1:6]]  # First 5 URLs
                    
        except Exception:
            pass  # Silent fail for Wayback
        
        return historical_data
    
    def open_in_browser(self, domain):
        """Open Wayback Machine analysis in browser"""
        try:
            import webbrowser
            wayback_url = f"https://web.archive.org/web/*/{domain}"
            ColorOutput.info(f"Wayback Machine: {wayback_url}")
            
            # Auto-open without prompt
            webbrowser.open(wayback_url)
            ColorOutput.success("Opened Wayback Machine in browser")
                
        except ImportError:
            ColorOutput.info(f"Wayback URL: https://web.archive.org/web/*/{domain}")

# Advanced Email Harvester - FIXED VERSION with enhanced filtering
class AdvancedEmailHarvester:
    def harvest_emails(self, domain, crawled_urls):
        """Enhanced email harvesting from crawled content with duplicate removal - FIXED VERSION"""
        harvested_emails = set()
        
        # Check common email patterns in crawled URLs and content
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Sample some URLs for email harvesting
        sample_urls = list(crawled_urls)[:10]  # Check first 10 URLs to avoid memory issues
        
        for url in sample_urls:
            try:
                response = requests.get(url, timeout=10)
                emails = re.findall(email_pattern, response.text)
                for email in emails:
                    # Enhanced email validation - REMOVED DOMAIN RESTRICTION
                    if (self._is_valid_email(email) and
                        not self._is_false_positive_email(email) and
                        self._is_likely_real_email(email)):
                        harvested_emails.add(email)
            except:
                continue
        
        # Convert to list and display unique emails only
        unique_emails = list(harvested_emails)
        
        # FIXED: Always show emails found, don't show warning if emails are found
        if unique_emails:
            ColorOutput.success(f"Found {len(unique_emails)} unique email addresses:")
            for email in unique_emails:
                ColorOutput.finding(f"Valid email found: {email}")
        else:
            ColorOutput.warning("No valid email addresses found")
        
        return unique_emails
    
    def _is_valid_email(self, email):
        """Validate email format and structure"""
        email_lower = email.lower()
        
        # Common false positive patterns - UPDATED
        false_positives = [
            r'noreply@', r'no-reply@', r'support@.*\.test', r'info@.*\.local',
            r'admin@.*\.local', r'root@localhost', r'postmaster@', r'webmaster@',
            r'example\.com', r'test\.com', r'domain\.com', r'sentry\.', r'wixpress\.com',
            r'^[a-f0-9]{32}@',  # hex hashes
            r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@',  # UUIDs
        ]
        
        # Check for false positives
        if any(re.search(pattern, email_lower) for pattern in false_positives):
            return False
        
        # Basic email validation
        if (len(email) < 6 or 
            '..' in email or 
            email.count('@') != 1 or
            email.startswith('.') or 
            email.endswith('.')):
            return False
        
        return True
    
    def _is_false_positive_email(self, email):
        """Check for common false positive email addresses - UPDATED"""
        false_positive_domains = [
            'example.com', 'domain.com', 'email.com', 'test.com',
            'yourdomain.com', 'sentry.io', 'w.org', 'github.com',
            'localhost', '127.0.0.1', 'your-email.com', 'company.com',
            'wixpress.com', 'sentry-next.wixpress.com', 'sentry.wixpress.com',
            'placeholder.com', 'fake.com', 'test.org', 'example.org'
        ]
        
        email_lower = email.lower()
        return any(domain in email_lower for domain in false_positive_domains)
    
    def _is_likely_real_email(self, email):
        """Check if email appears to be from a real person/organization - UPDATED"""
        email_lower = email.lower()
        
        # Common real email patterns
        real_patterns = [
            r'^[a-zA-Z]+\.[a-zA-Z]+@',  # first.last@domain
            r'^[a-zA-Z]+@',              # first@domain
            r'^[a-zA-Z][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # general valid email
        ]
        
        # Common automated/system email patterns to exclude - UPDATED
        system_patterns = [
            r'^[a-f0-9]+@',              # hex hashes
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@',  # UUIDs
            r'^[0-9]+@',                 # numeric-only usernames
            r'^[a-z0-9]{32}@',           # 32-character hashes
            r'@sentry\.',                # Sentry-related
            r'@.*\.sentry\.',            # Any subdomain of sentry
            r'@.*\.local$',              # Local domains
            r'@.*\.test$',               # Test domains
            r'@wixpress\.com$',          # Wixpress domains
        ]
        
        # Must match real patterns
        if not any(re.search(pattern, email_lower) for pattern in real_patterns):
            return False
        
        # Must NOT match system patterns
        if any(re.search(pattern, email_lower) for pattern in system_patterns):
            return False
        
        return True

# PDF EXTRACTOR
class PDFExtractor:
    def open_pdf_search(self, domain):
        """Open PDF search in browser"""
        try:
            import webbrowser
            
            ColorOutput.info("PDF SEARCH AUTOMATION")
            
            # Create multiple search queries for PDFs
            searches = [
                f"site:{domain} filetype:pdf",
                f"site:{domain} ext:pdf", 
            ]
            
            ColorOutput.info(f"Opening PDF search for: {domain}")
            
            # Open each search in browser
            for search in searches:
                google_url = f"https://www.google.com/search?q={urllib.parse.quote(search)}"
                
                # Open in browser
                webbrowser.open(google_url)
                time.sleep(0.5)
            
            ColorOutput.success("PDF search opened in browser")
            
        except Exception:
            ColorOutput.info("Manual PDF Search URLs:")
            ColorOutput.info(f"Google: https://www.google.com/search?q=site:{domain}+filetype:pdf")

# Technology Detector
class TechnologyDetector:
    def __init__(self):
        # Comprehensive technology patterns
        self.tech_patterns = {
            # CMS
            'WordPress': [
                r'wp-content', r'wp-includes', r'wordpress', r'/wp-json/', 
                r'wordpress', r'wp-admin', r'generator.*wordpress'
            ],
            'Joomla': [
                r'joomla', r'/media/jui/', r'/media/system/', r'generator.*joomla'
            ],
            'Drupal': [
                r'drupal', r'sites/all/', r'/misc/drupal', r'generator.*drupal'
            ],
            'Magento': [
                r'magento', r'/static/frontend/', r'/static/version'
            ],
            'Shopify': [
                r'shopify', r'cdn.shopify.com'
            ],
            
            # Web Servers
            'Nginx': [
                r'nginx', r'ngin[x|g]'
            ],
            'Apache': [
                r'apache', r'httpd', r'Apache'
            ],
            'IIS': [
                r'microsoft-iis', r'iis', r'x-powered-by.*iis'
            ],
            
            # Programming Languages
            'PHP': [
                r'\.php', r'php', r'x-powered-by.*php', r'phppython'
            ],
            'Python': [
                r'python', r'django', r'flask', r'werkzeug', r'wsgi'
            ],
            'Node.js': [
                r'node\.js', r'express', r'npm', r'x-powered-by.*node'
            ],
            'Ruby': [
                r'ruby', r'rails', r'rack', r'passenger'
            ],
            'Java': [
                r'java', r'jsp', r'servlet', r'tomcat', r'jboss'
            ],
            'ASP.NET': [
                r'asp\.net', r'\.aspx', r'x-aspnet-version'
            ],
            
            # Frontend Frameworks
            'React': [
                r'react', r'react-dom', r'react\\.js'
            ],
            'Vue.js': [
                r'vue', r'vue\\.js', r'vue-router'
            ],
            'Angular': [
                r'angular', r'ng-', r'angular\.js'
            ],
            'jQuery': [
                r'jquery', r'jquery\\.js'
            ],
            'Bootstrap': [
                r'bootstrap', r'bootstrap\\.css'
            ],
            
            # CDN & Security
            'Cloudflare': [
                r'cloudflare', r'cf-ray', r'__cfduid'
            ],
            'CloudFront': [
                r'cloudfront', r'aws.*cloudfront'
            ],
            'Akamai': [
                r'akamai', r'akamaiedge'
            ],
            
            # Analytics & Marketing
            'Google Analytics': [
                r'google-analytics', r'ga\.js', r'analytics\.js', r'gtag', r'ga\(', r'google.*analytics'
            ],
            'Google Tag Manager': [
                r'googletagmanager', r'gtm\.js'
            ],
            'Facebook Pixel': [
                r'facebook.*pixel', r'fbq\(', r'connect\.facebook\.net.*pixel'
            ],
            'Hotjar': [
                r'hotjar', r'hj.*js'
            ],
            
            # Database
            'MySQL': [
                r'mysql', r'mysqli'
            ],
            'MongoDB': [
                r'mongodb', r'mongo'
            ],
            'PostgreSQL': [
                r'postgresql', r'postgres'
            ],
            
            # E-commerce
            'WooCommerce': [
                r'woocommerce', r'wc-'
            ],
            'PayPal': [
                r'paypal', r'ppobjects'
            ],
            'Stripe': [
                r'stripe', r'stripe\.js'
            ]
        }
    
    def detect_technologies(self, url):
        """Improved technology detection with multiple methods"""
        technologies = set()
        
        try:
            response = requests.get(url, timeout=15, verify=False)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # Method 1: Check headers
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, headers, re.IGNORECASE):
                        technologies.add(tech)
                        break
            
            # Method 2: Check HTML content
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        technologies.add(tech)
                        break
            
            # Method 3: Check specific meta tags and scripts
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check generator meta tag
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator:
                generator_content = generator.get('content', '').lower()
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, generator_content, re.IGNORECASE):
                            technologies.add(tech)
            
            # Check script sources
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, src, re.IGNORECASE):
                            technologies.add(tech)
            
            # Check link hrefs for CSS frameworks
            for link in soup.find_all('link', href=True):
                href = link['href'].lower()
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, href, re.IGNORECASE):
                            technologies.add(tech)
                            
        except Exception as e:
            # Silent fail for tech detection
            pass
        
        return list(technologies)

class BuiltWithAutomation:
    def open_in_browser(self, domain):
        """Open BuiltWith analysis in browser"""
        try:
            import webbrowser
            builtwith_url = f"https://builtwith.com/?{domain}"
            ColorOutput.info(f"BuiltWith: {builtwith_url}")
            
            # Auto-open without prompt
            webbrowser.open(builtwith_url)
            ColorOutput.success("Opened BuiltWith in browser")
                
        except ImportError:
            ColorOutput.info(f"BuiltWith URL: https://builtwith.com/?{domain}")

class WebCrawler:
    def __init__(self, config, proxy=None):
        self.config = config
        self.proxy = proxy
        self.visited_urls = set()
        self.discovered_urls = set()
        self.session = self._create_session()
        self.pattern_matcher = PatternMatcher()
    
    def _create_session(self):
        session = requests.Session()
        session.headers.update({'User-Agent': self.config.USER_AGENT})
        
        if self.proxy:
            if self.proxy.startswith('socks'):
                session.proxies = {'http': self.proxy, 'https': self.proxy}
            else:
                session.proxies = {'http': self.proxy, 'https': self.proxy}
        
        return session
    
    def fetch_url(self, url):
        """Fetch URL content using requests"""
        try:
            # Skip email protection and other problematic URLs
            if URLUtils.should_skip_url(url):
                return None, None, None
                
            response = self.session.get(url, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            return response.text, response.headers, response.url
        except Exception:
            return None, None, None
    
    def discover_urls(self, start_url):
        """Discover URLs from robots.txt, sitemap, and page content"""
        discovered = set()
        
        # Discover from robots.txt
        robots_url = urllib.parse.urljoin(start_url, '/robots.txt')
        robots_urls = self._parse_robots_txt(robots_url)
        discovered.update(robots_urls)
        
        # Discover from sitemap
        sitemap_urls = self._parse_sitemap(start_url)
        discovered.update(sitemap_urls)
        
        # Discover from initial page
        initial_urls = self._extract_urls_from_page(start_url)
        discovered.update(initial_urls)
        
        return discovered
    
    def _parse_robots_txt(self, robots_url):
        """Parse robots.txt for URLs"""
        urls = set()
        try:
            response = self.session.get(robots_url, timeout=self.config.TIMEOUT)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Allow:') or line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urllib.parse.urljoin(robots_url, path)
                            if URLUtils.is_valid_url(full_url) and not URLUtils.should_skip_url(full_url):
                                urls.add(full_url)
                if urls:
                    ColorOutput.success(f"Found {len(urls)} URLs in robots.txt")
        except Exception:
            pass
        return urls
    
    def _parse_sitemap(self, base_url):
        """Parse sitemap.xml for URLs"""
        urls = set()
        sitemap_urls = [
            urllib.parse.urljoin(base_url, '/sitemap.xml'),
            urllib.parse.urljoin(base_url, '/sitemap_index.xml'),
            urllib.parse.urljoin(base_url, '/sitemap/')
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                response = self.session.get(sitemap_url, timeout=self.config.TIMEOUT)
                if response.status_code == 200:
                    # Use XML parser for sitemaps
                    try:
                        soup = BeautifulSoup(response.content, 'xml')
                    except:
                        soup = BeautifulSoup(response.content, 'lxml-xml')
                    
                    # Find all URLs in sitemap
                    for loc in soup.find_all('loc'):
                        url = loc.text.strip()
                        if URLUtils.is_valid_url(url) and not URLUtils.should_skip_url(url):
                            urls.add(url)
                    if urls:
                        ColorOutput.success(f"Found {len(urls)} URLs in sitemap")
            except Exception:
                continue
        
        return urls
    
    def _extract_urls_from_page(self, url):
        """Extract URLs from page content"""
        urls = set()
        content, headers, final_url = self.fetch_url(url)
        
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract from href attributes
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(final_url, href)
                if URLUtils.is_valid_url(full_url) and not URLUtils.should_skip_url(full_url):
                    urls.add(full_url)
        
        return urls
    
    def crawl(self, start_url, max_pages=None, max_depth=None):
        """Main crawling function"""
        if max_pages is None:
            max_pages = self.config.MAX_PAGES
        if max_depth is None:
            max_depth = self.config.MAX_DEPTH
        
        queue = [(start_url, 0)]
        all_findings = {
            'emails': set(),
            'social_media': {},
            'cloud_storage': {},
            'subdomains': set(),
            'files': {},
            'login_pages': set(),
            'crawled_links': set(),
            'html_comments': set(),
            'js_sources': set(),
            'marketing_tags': {},
            'interesting_findings': {}
        }
        
        # Initial discovery
        ColorOutput.info("Starting URL discovery...")
        discovered_urls = self.discover_urls(start_url)
        for url in discovered_urls:
            if url not in self.visited_urls and not URLUtils.should_skip_url(url):
                queue.append((url, 1))
        
        processed_count = 0
        while queue and len(self.visited_urls) < max_pages and processed_count < 50:  # Safety limit
            url, depth = queue.pop(0)
            
            if url in self.visited_urls or depth > max_depth or URLUtils.should_skip_url(url):
                continue
            
            ColorOutput.info(f"Crawling: {url} (Depth: {depth})")
            
            content, headers, final_url = self.fetch_url(url)
            if content:
                self.visited_urls.add(url)
                all_findings['crawled_links'].add(final_url)
                
                # Extract data
                extractor = DataExtractor(start_url)
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract various data types
                self._update_findings(all_findings, extractor, content, soup, final_url)
                
                # Discover new URLs
                if depth < max_depth:
                    new_urls = self._extract_urls_from_page(url)
                    for new_url in new_urls:
                        if (new_url not in self.visited_urls and 
                            new_url not in [u for u, d in queue] and 
                            len(self.visited_urls) < max_pages and
                            not URLUtils.should_skip_url(new_url)):
                            queue.append((new_url, depth + 1))
                
                time.sleep(self.config.CRAWL_DELAY)
                processed_count += 1
        
        # Extract subdomains and login pages from all crawled URLs
        extractor = DataExtractor(start_url)
        all_findings['subdomains'] = extractor.extract_subdomains(all_findings['crawled_links'])
        
        # Convert sets to lists for JSON serialization
        return self._format_findings(all_findings)
    
    def _update_findings(self, findings, extractor, content, soup, url):
        """Update findings with new extracted data"""
        # Emails - using sets to avoid duplicates
        emails = extractor.extract_emails(content)
        if emails:
            findings['emails'].update(emails)
        
        # Social media - FIXED: Consistent output format for all platforms
        social = extractor.extract_social_media(content)
        for platform, links in social.items():
            if platform not in findings['social_media']:
                findings['social_media'][platform] = set()
            findings['social_media'][platform].update(links)
            # FIXED: Use consistent [FINDING] format for all social media
            for link in links:
                ColorOutput.finding(f"Social media ({platform}): {link}")
        
        # Cloud storage
        cloud = extractor.extract_cloud_storage(content)
        for service, links in cloud.items():
            if service not in findings['cloud_storage']:
                findings['cloud_storage'][service] = set()
            findings['cloud_storage'][service].update(links)
            for link in links:
                ColorOutput.finding(f"Cloud storage ({service}): {link}")
        
        # Files
        files = extractor.extract_files([url])
        for file_type, file_urls in files.items():
            if file_type not in findings['files']:
                findings['files'][file_type] = set()
            findings['files'][file_type].update(file_urls)
            for file_url in file_urls:
                ColorOutput.finding(f"File ({file_type}): {file_url}")
        
        # HTML comments
        comments = extractor.extract_html_comments(content)
        if comments:
            findings['html_comments'].update(comments)
            for comment in comments[:3]:  # Show first 3 comments
                if len(comment) > 100:
                    ColorOutput.finding(f"HTML comment: {comment[:100]}...")
                else:
                    ColorOutput.finding(f"HTML comment: {comment}")
        
        # JS sources
        js_sources = extractor.extract_js_sources(soup)
        if js_sources:
            findings['js_sources'].update(js_sources)
        
        # Marketing tags
        tags = extractor.extract_marketing_tags(soup, content)
        for tag_type, value in tags.items():
            if tag_type not in findings['marketing_tags']:
                findings['marketing_tags'][tag_type] = set()
            if isinstance(value, list):
                findings['marketing_tags'][tag_type].update(value)
            else:
                findings['marketing_tags'][tag_type].add(value)
        
        # Interesting findings
        interesting = extractor.extract_interesting_findings(soup, content, url)
        for finding_type, value in interesting.items():
            if finding_type not in findings['interesting_findings']:
                findings['interesting_findings'][finding_type] = set()
            if isinstance(value, list):
                findings['interesting_findings'][finding_type].update(value)
                for val in value:
                    ColorOutput.finding(f"Interesting finding ({finding_type}): {val}")
            else:
                findings['interesting_findings'][finding_type].add(value)
                ColorOutput.finding(f"Interesting finding ({finding_type}): {value}")
    
    def _format_findings(self, findings):
        """Convert sets to lists for JSON output"""
        formatted = {}
        for key, value in findings.items():
            if isinstance(value, set):
                formatted[key] = list(value)
            elif isinstance(value, dict):
                formatted[key] = {}
                for subkey, subvalue in value.items():
                    if isinstance(subvalue, set):
                        formatted[key][subkey] = list(subvalue)
                    else:
                        formatted[key][subkey] = subvalue
            else:
                formatted[key] = value
        return formatted

class WebReconPro:
    def __init__(self, config):
        self.config = config
        self.results = {}
    
    def run_advanced_reconnaissance(self, start_url, max_pages=None, max_depth=None, output_file=None,
                                  enable_dns=True, enable_whois=True, enable_wayback=True, 
                                  enable_builtwith=True, enable_dnsdumpster=True):
        """Advanced reconnaissance with all features (SSL removed)"""
        ColorOutput.info(f"Starting WebRecon Pro against: {start_url}")
        ColorOutput.info(f"Timestamp: {datetime.now().isoformat()}")
        
        # Validate URL
        if not URLUtils.is_valid_url(start_url):
            ColorOutput.error("Invalid URL provided")
            return
        
        # Create output directory
        os.makedirs(self.config.OUTPUT_DIR, exist_ok=True)
        
        # Set up proxy if configured
        proxy = self.config.HTTP_PROXY or self.config.SOCKS_PROXY
        
        crawler = None
        try:
            # Initialize crawler
            crawler = WebCrawler(self.config, proxy=proxy)
            
            # Perform crawling
            ColorOutput.info("Starting web crawling...")
            crawl_results = crawler.crawl(start_url, max_pages, max_depth)
            self.results.update(crawl_results)
            
            # Extract domain for additional reconnaissance
            domain = URLUtils.get_domain(start_url)
            
            # DNSDumpster Automation
            if enable_dnsdumpster:
                ColorOutput.info("DNSDumpster domain IP analysis...")
                dnsdumpster = DNSDumpsterAutomation()
                domain_ip_info = dnsdumpster.get_domain_ip_info(domain)
                if domain_ip_info:
                    self.results['domain_ip_info'] = domain_ip_info
                # Automatically open DNSDumpster in browser with domain pre-filled
                dnsdumpster.open_in_browser(domain)
            
            # DNS Reconnaissance
            if enable_dns:
                ColorOutput.info("Performing DNS reconnaissance...")
                dns_recon = DNSRecon()
                dns_info = dns_recon.gather_dns_info(domain)
                if dns_info:
                    self.results['dns_info'] = dns_info
                    ColorOutput.success("DNS reconnaissance completed")
            
            # WHOIS Lookup - FIXED
            if enable_whois:
                ColorOutput.info("Performing WHOIS lookup...")
                whois_lookup = WHOISLookup()
                whois_info = whois_lookup.get_whois_info(domain)
                if whois_info:
                    self.results['whois_info'] = whois_info
                    ColorOutput.success("WHOIS lookup completed")
                else:
                    # If WHOIS API fails, we still open browser lookup which is more reliable
                    ColorOutput.info("Using browser-based WHOIS lookup (more reliable)")
                
                # Always open browser WHOIS lookup - this is the reliable method
                whois_lookup.open_in_browser(domain)
            
            # Wayback Machine
            if enable_wayback:
                ColorOutput.info("Wayback Machine historical analysis...")
                wayback = WaybackMachine()
                self.results['wayback_data'] = wayback.get_historical_data(domain)
                wayback.open_in_browser(domain)
            
            # Advanced Email Harvesting - FIXED VERSION with enhanced filtering
            ColorOutput.info("Performing advanced email harvesting...")
            email_harvester = AdvancedEmailHarvester()
            additional_emails = email_harvester.harvest_emails(domain, self.results['crawled_links'])
            # Merge and deduplicate all emails
            all_emails = set(self.results.get('emails', []) + additional_emails)
            self.results['emails'] = list(all_emails)
            
            # PDF EXTRACTION
            pdf_extractor = PDFExtractor()
            pdf_extractor.open_pdf_search(domain)
            
            # Technology detection
            ColorOutput.info("Performing technology detection...")
            tech_detector = TechnologyDetector()
            technologies = tech_detector.detect_technologies(start_url)
            
            self.results['technologies'] = {
                'detected': technologies
            }
            
            # Display technology findings
            if technologies:
                ColorOutput.success(f"Technologies detected: {len(technologies)}")
                for tech in technologies:
                    ColorOutput.finding(f"Technology: {tech}")
            else:
                ColorOutput.warning("No technologies detected")
            
            # BuiltWith Automation (optional)
            if enable_builtwith:
                ColorOutput.info("BuiltWith technology analysis...")
                builtwith = BuiltWithAutomation()
                builtwith.open_in_browser(domain)
            
            # Generate report
            self._generate_report(output_file, domain)
            
            ColorOutput.success("Advanced reconnaissance completed successfully!")
            
        except Exception as e:
            ColorOutput.error(f"Reconnaissance failed: {e}")
        finally:
            # Cleanup
            if crawler:
                pass
    
    def _generate_report(self, output_file=None, domain=None):
        """Generate comprehensive report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize domain for filename
            if domain:
                safe_domain = "".join(c for c in domain if c.isalnum() or c in ('-', '_')).rstrip()
                output_file = f"{self.config.OUTPUT_DIR}/webrecon_{safe_domain}_{timestamp}.json"
            else:
                output_file = f"{self.config.OUTPUT_DIR}/webrecon_report_{timestamp}.json"
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save JSON report
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            # Print summary
            self._print_summary()
            
            ColorOutput.success(f"Full report saved to: {output_file}")
        except Exception as e:
            ColorOutput.error(f"Failed to save report: {e}")
            # Fallback to simple print
            self._print_summary()
    
    def _print_summary(self):
        """Print reconnaissance summary"""
        ColorOutput.info("\n" + "="*60)
        ColorOutput.info("WEBRECON PRO - RECONNAISSANCE SUMMARY")
        ColorOutput.info("="*60)
        
        stats = {
            'Crawled Links': len(self.results.get('crawled_links', [])),
            'Valid Emails Found': len(self.results.get('emails', [])),
            'Subdomains Found': len(self.results.get('subdomains', [])),
            'Social Media Links': sum(len(v) for v in self.results.get('social_media', {}).values()),
            'Cloud Storage Links': sum(len(v) for v in self.results.get('cloud_storage', {}).values()),
            'Files Found': sum(len(v) for v in self.results.get('files', {}).values()),
            'Login Pages': len(self.results.get('login_pages', [])),
            'HTML Comments': len(self.results.get('html_comments', [])),
            'JS Sources': len(self.results.get('js_sources', [])),
            'Technologies Detected': len(self.results.get('technologies', {}).get('detected', []))
        }
        
        for category, count in stats.items():
            if count > 0:
                ColorOutput.finding(f"{category}: {count}")
            else:
                ColorOutput.warning(f"{category}: {count}")
        
        # Print Domain IP Information if available
        if self.results.get('domain_ip_info'):
            ColorOutput.info("\nDOMAIN IP INFORMATION:")
            ip_info = self.results['domain_ip_info']
            if ip_info.get('primary_ip'):
                ColorOutput.finding(f"  Primary IP: {ip_info['primary_ip']}")
            if ip_info.get('reverse_dns') and ip_info['reverse_dns'] != "Not available":
                ColorOutput.finding(f"  Reverse DNS: {ip_info['reverse_dns']}")
        
        # Print DNS information if available
        if self.results.get('dns_info'):
            ColorOutput.info("\nDNS INFORMATION:")
            for record_type, records in self.results['dns_info'].items():
                if records:
                    ColorOutput.finding(f"  {record_type.upper()}: {', '.join(records)}")
        
        # Print WHOIS information if available
        if self.results.get('whois_info'):
            ColorOutput.info("\nWHOIS INFORMATION:")
            whois_info = self.results['whois_info']
            if whois_info.get('registrar'):
                ColorOutput.finding(f"  Registrar: {whois_info['registrar']}")
            if whois_info.get('creation_date'):
                ColorOutput.finding(f"  Created: {whois_info['creation_date']}")
            if whois_info.get('org'):
                ColorOutput.finding(f"  Organization: {whois_info['org']}")
            if whois_info.get('country'):
                ColorOutput.finding(f"  Country: {whois_info['country']}")
        
        # Print unique emails found
        if self.results.get('emails'):
            ColorOutput.info("\nUNIQUE EMAILS FOUND:")
            for email in self.results['emails']:
                ColorOutput.finding(f"  {email}")
        
        # Print LinkedIn URLs specifically
        if self.results.get('social_media', {}).get('linkedin'):
            ColorOutput.info("\nVALID LINKEDIN URLS FOUND:")
            for linkedin_url in self.results['social_media']['linkedin']:
                ColorOutput.finding(f"  LinkedIn: {linkedin_url}")
        
        # Print technology summary
        if self.results.get('technologies', {}).get('detected'):
            ColorOutput.info("\nTECHNOLOGY SUMMARY:")
            techs = self.results['technologies']['detected']
            ColorOutput.finding(f"  Detected: {', '.join(techs)}")

def display_usage():
    """Display comprehensive usage information"""
    print(f"""
{Fore.CYAN}WebRecon Pro - Advanced OSINT Web Reconnaissance Tool
{Fore.YELLOW}Usage Guide:{Style.RESET_ALL}
{Fore.GREEN}Basic Usage:{Style.RESET_ALL}
  python3 webrecon_pro.py https://example.com
{Fore.GREEN}Advanced Options:{Style.RESET_ALL}
  --max-pages NUM        Maximum pages to crawl (default: 100)
  --max-depth NUM        Maximum crawl depth (default: 2)
  --output FILE          Custom output file path
  --proxy URL            HTTP/SOCKS proxy (e.g., http://proxy:8080 or socks5://proxy:1080)
{Fore.GREEN}Feature Control:{Style.RESET_ALL}
  --no-dns               Disable DNS reconnaissance
  --no-whois             Disable WHOIS lookup
  --no-wayback           Disable Wayback Machine integration
  --no-builtwith         Disable BuiltWith technology analysis
  --no-dnsdumpster       Disable DNSDumpster domain IP analysis
{Fore.GREEN}Environment Variables:{Style.RESET_ALL}
  HTTP_PROXY             HTTP proxy URL
  SOCKS_PROXY            SOCKS proxy URL
{Fore.GREEN}Examples:{Style.RESET_ALL}
  {Fore.CYAN}# Basic reconnaissance{Style.RESET_ALL}
  python3 webrecon_pro.py https://example.com
  {Fore.CYAN}# With proxy and custom output{Style.RESET_ALL}
  python3 webrecon_pro.py https://example.com --proxy socks5://127.0.0.1:9050 --output results.json
  {Fore.CYAN}# Minimal reconnaissance (crawling only){Style.RESET_ALL}
  python3 webrecon_pro.py https://example.com --no-dns --no-whois --no-wayback --no-builtwith --no-dnsdumpster
{Fore.YELLOW}Features:{Style.RESET_ALL}
  • Web crawling with configurable depth and page limits
  • Email address extraction with enhanced false positive filtering
  • Social media profile discovery
  • Technology stack detection
  • DNS information gathering
  • WHOIS lookup (browser-based for reliability)
  • DNSDumpster domain IP analysis (automated browser lookup)
  • Wayback Machine historical data
  • PDF content extraction
  • Cloud storage discovery
  • Marketing tag detection
  • JSON report generation
{Fore.YELLOW}Enhanced LinkedIn Detection:{Style.RESET_ALL}
  • Fixed LinkedIn URL patterns to find valid company pages
  • Proper LinkedIn URL formats: /company/, /in/, /showcase/, /school/, /pages/
  • Filters out invalid LinkedIn URLs that cause "Page not found" errors
  • Consistent [FINDING] Social media (linkedin): output format
{Fore.YELLOW}Output:{Style.RESET_ALL}
  Results are saved to JSON files in the 'webrecon_output' directory
  Interactive features automatically open in browser with domain pre-filled
  Real-time findings are displayed with color-coded output
  Duplicate emails are automatically filtered and shown only once
  WHOIS uses browser-based lookups for maximum reliability
    """)

def main():
    banner = f"""
{Fore.CYAN}
 █████   ███   █████          █████     ███████████                                        
░░███   ░███  ░░███          ░░███     ░░███░░░░░███                                       
 ░███   ░███   ░███   ██████  ░███████  ░███    ░███   ██████   ██████   ██████  ████████  
 ░███   ░███   ░███  ███░░███ ░███░░███ ░██████████   ███░░███ ███░░███ ███░░███ ░░███░░███ 
 ░░███  █████  ███  ░███████  ░███ ░███ ░███░░░░░███ ░███████ ░███ ░░░ ░███ ░███  ░███ ░███ 
  ░░░█████░█████░   ░███░░░   ░███ ░███ ░███    ░███ ░███░░░  ░███  ███░███ ░███  ░███ ░███ 
    ░░███ ░░███     ░░██████  ████████  █████   █████░░██████ ░░██████ ░░██████  ████ █████
     ░░░   ░░░       ░░░░░░  ░░░░░░░░  ░░░░░   ░░░░░  ░░░░░░   ░░░░░░   ░░░░░░  ░░░░ ░░░░░ 
                                                                                           
{Fore.YELLOW}                          Advanced OSINT Web Reconnaissance Tool
{Fore.WHITE}                          Author: D4rk_Intel | Project: OSINT Reconnaissance Tool
{Style.RESET_ALL}
    """
    
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='WebRecon Pro - Advanced OSINT Web Reconnaissance Tool',
        add_help=False
    )
    
    # Required arguments
    parser.add_argument('url', nargs='?', help='Target URL for reconnaissance')
    
    # Optional arguments
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum pages to crawl (default: 100)')
    parser.add_argument('--max-depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--proxy', help='HTTP/SOCKS proxy (overrides config)')
    
    # Feature control
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS reconnaissance')
    parser.add_argument('--no-whois', action='store_true', help='Disable WHOIS lookup')
    parser.add_argument('--no-wayback', action='store_true', help='Disable Wayback Machine')
    parser.add_argument('--no-builtwith', action='store_true', help='Disable BuiltWith automation')
    parser.add_argument('--no-dnsdumpster', action='store_true', help='Disable DNSDumpster domain IP analysis')
    
    # Help
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    args = parser.parse_args()
    
    # Show help if requested or no URL provided
    if args.help or not args.url:
        display_usage()
        return
    
    # Update config with command line arguments
    config = Config()
    if args.proxy:
        if args.proxy.startswith('socks'):
            config.SOCKS_PROXY = args.proxy
        else:
            config.HTTP_PROXY = args.proxy
    
    config.MAX_PAGES = args.max_pages
    config.MAX_DEPTH = args.max_depth
    
    # Initialize and run advanced reconnaissance
    recon = WebReconPro(config)
    recon.run_advanced_reconnaissance(
        start_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        output_file=args.output,
        enable_dns=not args.no_dns,
        enable_whois=not args.no_whois,
        enable_wayback=not args.no_wayback,
        enable_builtwith=not args.no_builtwith,
        enable_dnsdumpster=not args.no_dnsdumpster
    )

if __name__ == '__main__':
    main() jelaskan tentang tools
