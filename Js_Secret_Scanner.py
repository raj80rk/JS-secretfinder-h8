#!/usr/bin/env python3
"""
Advanced JavaScript & JSON Crawler with Secret Scanner
Enhanced version with better secret detection, reporting, and analysis capabilities
"""

import argparse
import sys
import os
import json
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
import hashlib
import logging
from datetime import datetime

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import colorama
    from colorama import Fore, Back, Style
    from bs4 import BeautifulSoup
    import yaml
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install requests colorama beautifulsoup4 pyyaml")
    sys.exit(1)

# Initialize colorama
colorama.init(autoreset=True)

@dataclass
class SecretMatch:
    """Data class for secret matches"""
    pattern_name: str
    matched_text: str
    line_number: int
    column: int
    context: str = ""
    confidence: str = "medium"
    file_path: str = ""
    
@dataclass
class FileInfo:
    """Enhanced file information"""
    url: str
    size: int
    content_type: str
    status_code: int
    hash_md5: str
    hash_sha256: str
    secrets: List[SecretMatch]
    response_time: float
    headers: Dict
    extracted_urls: List[str] = None
    
class AdvancedSecretScanner:
    """Advanced secret detection with multiple pattern types"""
    
    def __init__(self):
        self.patterns = {
            # API Keys
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'confidence': 'high',
                'description': 'AWS Access Key ID'
            },
            'aws_secret_key': {
                'pattern': r'aws.{0,20}?[\'\"\\s][0-9a-zA-Z\\/+]{40}[\'\"\\s]',
                'confidence': 'high',
                'description': 'AWS Secret Access Key'
            },
            'github_token': {
                'pattern': r'gh[pousr]_[A-Za-z0-9_]{36}',
                'confidence': 'high',
                'description': 'GitHub Personal Access Token'
            },
            'generic_api_key': {
                'pattern': r'[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
                'confidence': 'medium',
                'description': 'Generic API Key'
            },
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                'confidence': 'high',
                'description': 'JWT Token'
            },
            'stripe_key': {
                'pattern': r'(pk|sk)_(test|live)_[0-9A-Za-z]{24,}',
                'confidence': 'high',
                'description': 'Stripe API Key'
            },
            'google_api_key': {
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'confidence': 'high',
                'description': 'Google API Key'
            },
            'slack_webhook': {
                'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}',
                'confidence': 'high',
                'description': 'Slack Webhook URL'
            },
            'discord_webhook': {
                'pattern': r'https://discord(?:app)?\.com/api/webhooks/[0-9]{18}/[A-Za-z0-9_-]{68}',
                'confidence': 'high',
                'description': 'Discord Webhook URL'
            },
            'password_field': {
                'pattern': r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                'confidence': 'medium',
                'description': 'Password Field'
            },
            'database_url': {
                'pattern': r'(?:postgresql|mysql|mongodb)://[^\\s]+:[^\\s]+@[^\\s/]+',
                'confidence': 'high',
                'description': 'Database Connection String'
            },
            'private_key': {
                'pattern': r'-----BEGIN[ A-Z]*PRIVATE KEY-----',
                'confidence': 'high',
                'description': 'Private Key'
            },
            'secret_generic': {
                'pattern': r'["\']?(?:secret|token|key)["\']?\s*[:=]\s*["\'][^"\']{16,}["\']',
                'confidence': 'low',
                'description': 'Generic Secret Pattern'
            },
            'base64_long': {
                'pattern': r'[A-Za-z0-9+/]{64,}={0,2}',
                'confidence': 'low',
                'description': 'Long Base64 String (Potential Secret)'
            },
            'hex_key': {
                'pattern': r'[a-fA-F0-9]{32,}',
                'confidence': 'low',
                'description': 'Hexadecimal Key Pattern'
            }
        }
        
        # Entropy-based detection for high-entropy strings
        self.min_entropy = 4.5
        self.min_length = 20
        
    def calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(string.count(chr(x))) / len(string)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        return entropy
    
    def scan_content(self, content: str, file_path: str = "") -> List[SecretMatch]:
        """Scan content for secrets using multiple detection methods"""
        secrets = []
        lines = content.split('\n')
        
        # Pattern-based detection
        for pattern_name, pattern_info in self.patterns.items():
            pattern = re.compile(pattern_info['pattern'], re.IGNORECASE | re.MULTILINE)
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    # Get context (surrounding lines)
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 1)
                    context = '\n'.join(lines[start_line:end_line])
                    
                    secret = SecretMatch(
                        pattern_name=pattern_name,
                        matched_text=match.group(0),
                        line_number=line_num,
                        column=match.start(),
                        context=context,
                        confidence=pattern_info['confidence'],
                        file_path=file_path
                    )
                    secrets.append(secret)
        
        # Entropy-based detection for high-entropy strings
        entropy_secrets = self._detect_high_entropy_strings(content, file_path)
        secrets.extend(entropy_secrets)
        
        return secrets
    
    def _detect_high_entropy_strings(self, content: str, file_path: str = "") -> List[SecretMatch]:
        """Detect high-entropy strings that might be secrets"""
        secrets = []
        lines = content.split('\n')
        
        # Look for quoted strings and variable assignments
        string_patterns = [
            r'["\']([^"\']{20,})["\']',  # Quoted strings
            r'=\s*([a-zA-Z0-9+/=]{20,})',  # Assignment values
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in string_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    candidate = match.group(1) if len(match.groups()) > 0 else match.group(0)
                    
                    if len(candidate) >= self.min_length:
                        entropy = self.calculate_entropy(candidate)
                        
                        if entropy >= self.min_entropy:
                            # Get context
                            start_line = max(0, line_num - 2)
                            end_line = min(len(lines), line_num + 1)
                            context = '\n'.join(lines[start_line:end_line])
                            
                            secret = SecretMatch(
                                pattern_name='high_entropy_string',
                                matched_text=candidate,
                                line_number=line_num,
                                column=match.start(),
                                context=context,
                                confidence='low',
                                file_path=file_path
                            )
                            secrets.append(secret)
        
        return secrets

class AdvancedCrawler:
    """Enhanced crawler with better functionality"""
    
    def __init__(self, threads: int = 5, timeout: int = 10, verbose: bool = False):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.found_files: List[FileInfo] = []
        self.processed_urls: Set[str] = set()
        self.session = self._create_session()
        self.secret_scanner = AdvancedSecretScanner()
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO if verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set headers to mimic a real browser
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        return session
    
    def _calculate_hashes(self, content: bytes) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes of content"""
        md5_hash = hashlib.md5(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        return md5_hash, sha256_hash
    
    def _extract_urls_from_content(self, content: str, base_url: str) -> List[str]:
        """Extract JavaScript and JSON URLs from HTML/JavaScript content"""
        urls = []
        
        # Common JS/JSON file patterns
        js_patterns = [
            r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
            r'href=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
            r'["\']([^"\']*\.json(?:\?[^"\']*)?)["\']',
            r'loadScript\(["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
            r'import.*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
            r'require\(["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                absolute_url = urllib.parse.urljoin(base_url, match)
                if absolute_url not in urls:
                    urls.append(absolute_url)
        
        return urls
    
    def _is_js_or_json_file(self, url: str, content_type: str) -> bool:
        """Check if URL or content type indicates JS/JSON file"""
        url_lower = url.lower()
        content_type_lower = content_type.lower()
        
        # Check URL extension
        js_extensions = ['.js', '.json', '.jsx', '.ts', '.vue', '.angular.js']
        if any(url_lower.endswith(ext) for ext in js_extensions):
            return True
        
        # Check content type
        js_content_types = [
            'application/javascript',
            'application/json',
            'text/javascript',
            'application/x-javascript',
            'text/x-javascript'
        ]
        if any(ct in content_type_lower for ct in js_content_types):
            return True
        
        return False
    
    def crawl_url(self, url: str, scan_secrets: bool = False, recursive: bool = False) -> Optional[FileInfo]:
        """Crawl a single URL and optionally scan for secrets"""
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=self.timeout, stream=True)
            response_time = time.time() - start_time
            
            content_type = response.headers.get('content-type', '').lower()
            
            # Check if it's a JS/JSON file or if we should process it anyway
            if not self._is_js_or_json_file(url, content_type) and not recursive:
                self.logger.info(f"Skipping non-JS/JSON file: {url}")
                return None
            
            # Get content
            content = response.text
            content_bytes = response.content
            
            # Calculate hashes
            md5_hash, sha256_hash = self._calculate_hashes(content_bytes)
            
            # Scan for secrets if requested
            secrets = []
            if scan_secrets:
                secrets = self.secret_scanner.scan_content(content, url)
            
            # Extract additional URLs if this is an HTML page or JS file
            extracted_urls = []
            if recursive:
                extracted_urls = self._extract_urls_from_content(content, url)
            
            file_info = FileInfo(
                url=url,
                size=len(content_bytes),
                content_type=content_type,
                status_code=response.status_code,
                hash_md5=md5_hash,
                hash_sha256=sha256_hash,
                secrets=secrets,
                response_time=response_time,
                headers=dict(response.headers),
                extracted_urls=extracted_urls
            )
            
            with self.lock:
                self.found_files.append(file_info)
                self.processed_urls.add(url)
            
            # Print immediate results
            self._print_file_result(file_info)
            
            return file_info
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error crawling {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error crawling {url}: {e}")
            return None
    
    def _print_file_result(self, file_info: FileInfo):
        """Print results for a single file"""
        status_color = Fore.GREEN if file_info.status_code == 200 else Fore.RED
        print(f"{status_color}[{file_info.status_code}]{Style.RESET_ALL} {file_info.url}")
        print(f"    Size: {file_info.size:,} bytes | Type: {file_info.content_type} | Time: {file_info.response_time:.2f}s")
        
        if file_info.secrets:
            print(f"    {Fore.RED}🚨 SECRETS FOUND: {len(file_info.secrets)}{Style.RESET_ALL}")
            for secret in file_info.secrets[:3]:  # Show first 3 secrets
                confidence_color = Fore.RED if secret.confidence == 'high' else Fore.YELLOW if secret.confidence == 'medium' else Fore.BLUE
                print(f"      {confidence_color}[{secret.confidence.upper()}]{Style.RESET_ALL} {secret.pattern_name}: {secret.matched_text[:50]}...")
        
        if file_info.extracted_urls:
            print(f"    📁 Extracted {len(file_info.extracted_urls)} additional URLs")
        
        print()
    
    def crawl_multiple(self, urls: List[str], scan_secrets: bool = False, recursive: bool = False) -> List[FileInfo]:
        """Crawl multiple URLs concurrently"""
        print(f"{Fore.CYAN}🚀 Starting crawler with {self.threads} threads{Style.RESET_ALL}")
        print(f"📊 Target URLs: {len(urls)}")
        print(f"🔍 Secret scanning: {'enabled' if scan_secrets else 'disabled'}")
        print(f"🔄 Recursive crawling: {'enabled' if recursive else 'disabled'}")
        print("=" * 70)
        
        all_urls_to_process = set(urls)
        processed = set()
        
        while all_urls_to_process - processed:
            current_batch = list(all_urls_to_process - processed)
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.crawl_url, url, scan_secrets, recursive): url 
                    for url in current_batch
                }
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    processed.add(url)
                    
                    try:
                        result = future.result()
                        if result and recursive and result.extracted_urls:
                            # Add newly discovered URLs
                            for new_url in result.extracted_urls:
                                if new_url not in all_urls_to_process:
                                    all_urls_to_process.add(new_url)
                    except Exception as e:
                        self.logger.error(f"Error processing {url}: {e}")
        
        return self.found_files

def print_banner():
    """Print an enhanced banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                 Advanced JS/JSON Secret Crawler              ║
║                        Enhanced Edition                      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def read_input_file(filename: str) -> List[str]:
    """Read URLs from input file"""
    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return urls
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file '{filename}' not found{Style.RESET_ALL}")
        sys.exit(1)

def save_results(results: List[FileInfo], output_file: str, format_type: str = 'json'):
    """Save results to file in various formats"""
    timestamp = datetime.now().isoformat()
    
    output_data = {
        'timestamp': timestamp,
        'total_files': len(results),
        'files_with_secrets': len([f for f in results if f.secrets]),
        'total_secrets': sum(len(f.secrets) for f in results),
        'results': [asdict(result) for result in results]
    }
    
    try:
        if format_type.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
        elif format_type.lower() == 'yaml':
            with open(output_file, 'w') as f:
                yaml.dump(output_data, f, default_flow_style=False)
        else:
            # CSV-like text format
            with open(output_file, 'w') as f:
                f.write(f"# JS/JSON Crawler Results - {timestamp}\n\n")
                for result in results:
                    f.write(f"URL: {result.url}\n")
                    f.write(f"Status: {result.status_code} | Size: {result.size} bytes\n")
                    if result.secrets:
                        f.write(f"SECRETS FOUND ({len(result.secrets)}):\n")
                        for secret in result.secrets:
                            f.write(f"  - {secret.pattern_name}: {secret.matched_text}\n")
                    f.write("\n" + "="*80 + "\n")
        
        print(f"{Fore.GREEN}✅ Results saved to: {output_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error saving results: {e}{Style.RESET_ALL}")

def print_summary(results: List[FileInfo]):
    """Print a comprehensive summary"""
    total_files = len(results)
    files_with_secrets = len([f for f in results if f.secrets])
    total_secrets = sum(len(f.secrets) for f in results)
    
    print(f"\n{Fore.CYAN}📊 CRAWLING SUMMARY{Style.RESET_ALL}")
    print("=" * 50)
    print(f"📁 Total files processed: {total_files}")
    print(f"🚨 Files with secrets: {files_with_secrets}")
    print(f"🔑 Total secrets found: {total_secrets}")
    
    if files_with_secrets > 0:
        print(f"\n{Fore.RED}⚠️  SECURITY ALERT: Secrets detected!{Style.RESET_ALL}")
        
        # Secret type breakdown
        secret_types = {}
        for result in results:
            for secret in result.secrets:
                secret_types[secret.pattern_name] = secret_types.get(secret.pattern_name, 0) + 1
        
        print(f"\n{Fore.YELLOW}🔍 Secret Types Found:{Style.RESET_ALL}")
        for secret_type, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {secret_type}: {count}")
    
    print(f"\n{Fore.GREEN}✅ Crawling completed!{Style.RESET_ALL}")

def save_urls_only(results: List[FileInfo], output_file: str):
    """Save only URLs to a text file for phase 2 processing"""
    try:
        with open(output_file, 'w') as f:
            f.write("# JavaScript and JSON URLs discovered\n")
            f.write(f"# Generated on: {datetime.now().isoformat()}\n\n")
            
            for result in results:
                f.write(f"{result.url}\n")
                
                # Add extracted URLs if available
                if result.extracted_urls:
                    for extracted_url in result.extracted_urls:
                        f.write(f"{extracted_url}\n")
        
        print(f"{Fore.GREEN}✅ URLs saved to: {output_file}{Style.RESET_ALL}")
        print(f"📊 Total URLs saved: {len(results) + sum(len(r.extracted_urls or []) for r in results)}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Error saving URLs: {e}{Style.RESET_ALL}")

def main():
    """Enhanced main function with two-phase workflow support"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced JS and JSON files crawler with comprehensive secret scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Two-Phase Workflow Examples:
  # Phase 1: Discover JS/JSON files and save URLs
  %(prog)s -l https://example.com -o discovered_urls.txt
  
  # Phase 2: Scan discovered files for secrets
  %(prog)s -il discovered_urls.txt --scan-secrets --threads 10 -o results.json
  
Single-Phase Examples:
  %(prog)s -l https://example.com --scan-secrets --discover-only
  %(prog)s -l https://example.com --scan-secrets --format yaml -o results.yaml
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-l', '--list', help="One or more target URLs", nargs='+')
    input_group.add_argument('-il', '--input', help="File containing list of URLs")
    
    # Output options
    parser.add_argument('-o', '--output', help="File to save output")
    parser.add_argument('--format', choices=['json', 'yaml', 'txt'], default='json',
                       help="Output format (default: json)")
    
    # Performance options
    parser.add_argument('-t', '--threads', type=int, help="Number of threads (1-20)", 
                       default=5, choices=range(1, 21))
    parser.add_argument('--timeout', type=int, help="Timeout for HTTP requests (5-30)", 
                       default=10, choices=range(5, 31))
    
    # Feature options
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help="Enable verbose logging")
    parser.add_argument('--scan-secrets', action='store_true', 
                       help="Scan JavaScript files for secrets")
    parser.add_argument('--discover-only', action='store_true',
                       help="Only discover JS/JSON files, don't scan content (Phase 1)")
    parser.add_argument('--recursive', action='store_true',
                       help="Recursively discover and crawl JS/JSON files from HTML pages")
    parser.add_argument('--min-entropy', type=float, default=4.5,
                       help="Minimum entropy for high-entropy string detection (default: 4.5)")
    
    # Advanced options
    parser.add_argument('--user-agent', help="Custom User-Agent string")
    parser.add_argument('--headers', help="Custom headers as JSON string")
    parser.add_argument('--proxy', help="Proxy URL (http://proxy:port)")
    
    args = parser.parse_args()
    
    # Determine workflow mode
    phase_1_mode = args.discover_only or (args.output and args.output.endswith('.txt') and not args.scan_secrets)
    
    if phase_1_mode:
        print(f"{Fore.CYAN}🔍 Running in Phase 1 mode: URL Discovery{Style.RESET_ALL}")
    elif args.input:
        print(f"{Fore.CYAN}🔍 Running in Phase 2 mode: Secret Scanning{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}🔍 Running in Single-Phase mode{Style.RESET_ALL}")
    
    # Get URLs
    if args.list:
        urls = args.list
    else:
        urls = read_input_file(args.input)
    
    if not urls:
        print(f"{Fore.RED}Error: No URLs provided{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create crawler
    crawler = AdvancedCrawler(
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Configure secret scanner
    if args.scan_secrets:
        crawler.secret_scanner.min_entropy = args.min_entropy
    
    # Apply custom settings
    if args.user_agent:
        crawler.session.headers['User-Agent'] = args.user_agent
    
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
            crawler.session.headers.update(custom_headers)
        except json.JSONDecodeError:
            print(f"{Fore.RED}Error: Invalid JSON in headers{Style.RESET_ALL}")
            sys.exit(1)
    
    if args.proxy:
        crawler.session.proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    # Start crawling
    try:
        # Phase 1: URL Discovery Mode
        if phase_1_mode:
            print(f"{Fore.YELLOW}📋 Phase 1: Discovering JS/JSON files...{Style.RESET_ALL}")
            results = crawler.crawl_multiple(
                urls=urls,
                scan_secrets=False,  # Don't scan in phase 1
                recursive=True  # Always use recursive in phase 1
            )
            
            if args.output:
                save_urls_only(results, args.output)
                print(f"\n{Fore.GREEN}✅ Phase 1 Complete! Use the following command for Phase 2:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}python crawler.py -il {args.output} --scan-secrets --threads 10 -o results.json{Style.RESET_ALL}")
            else:
                print_summary(results)
        
        # Phase 2 or Single-Phase: Secret Scanning Mode
        else:
            scan_secrets = args.scan_secrets or not phase_1_mode
            results = crawler.crawl_multiple(
                urls=urls,
                scan_secrets=scan_secrets,
                recursive=args.recursive
            )
            
            # Print summary
            print_summary(results)
            
            # Save results
            if args.output:
                save_results(results, args.output, args.format)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Crawling interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()