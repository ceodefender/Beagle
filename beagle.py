#!/usr/bin/env python3
"""
Beagle - Advanced Web Reconnaissance & Penetration Testing Tool
Author: CEO
Version: 1.1
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import hashlib
import re
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional
import dns.resolver
import requests
from bs4 import BeautifulSoup
import threading
from fake_useragent import UserAgent
import stem.process
from stem import Signal
from stem.control import Controller
import socks
import http.client
import urllib3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.tree import Tree
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
import nmap
import subprocess
import os
import sys

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

class BeagleScanner:
    def __init__(self, target: str, use_tor: bool = False):
        self.target = target
        self.use_tor = use_tor
        self.session = None
        self.results = {}
        self.ua = UserAgent()
        self.nm = nmap.PortScanner()
        
        # Initialize Tor if requested
        if self.use_tor:
            self._setup_tor()
    
    def _setup_tor(self):
        """Setup Tor proxy for anonymous scanning"""
        try:
            # Set up SOCKS5 proxy
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            # Test Tor connection
            test_session = requests.Session()
            test_session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            
            response = test_session.get('http://check.torproject.org')
            if 'Congratulations' in response.text:
                console.print("✅ [green]Tor connection established successfully[/green]")
            else:
                console.print("❌ [red]Tor connection failed[/red]")
                self.use_tor = False
                
        except Exception as e:
            console.print(f"❌ [red]Tor setup failed: {e}[/red]")
            self.use_tor = False
    
    async def _create_session(self):
        """Create aiohttp session with proper headers"""
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(verify_ssl=False)
        
        headers = {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        if self.use_tor:
            connector = aiohttp.TCPConnector(
                verify_ssl=False,
                family=socket.AF_INET,
                local_addr=('127.0.0.1', 9050)
            )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
    
    async def scan_ports(self):
        """Advanced port scanning with service detection"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🔍 Scanning ports...", total=100)
            
            try:
                # Common web ports + extended range
                ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                        993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 9000, 10000]
                
                open_ports = []
                
                for port in ports:
                    progress.update(task, advance=100/len(ports))
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((self.target, port))
                        sock.close()
                        
                        if result == 0:
                            # Get service name
                            try:
                                service = socket.getservbyport(port, 'tcp')
                            except:
                                service = "unknown"
                            
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'state': 'open'
                            })
                    except:
                        pass
                
                self.results['ports'] = open_ports
                progress.update(task, completed=100)
                
            except Exception as e:
                console.print(f"❌ [red]Port scan error: {e}[/red]")
    
    async def detect_technologies(self):
        """Comprehensive technology detection"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🔧 Detecting technologies...", total=100)
            
            technologies = {
                'web_servers': [],
                'frameworks': [],
                'programming_languages': [],
                'javascript_libraries': [],
                'databases': [],
                'cms': [],
                'caching': [],
                'cdn': [],
                'security': [],
                'analytics': [],
                'widgets': []
            }
            
            try:
                # Get main page content
                async with self.session.get(f"http://{self.target}") as response:
                    content = await response.text()
                    headers = dict(response.headers)
                
                progress.update(task, advance=20)
                
                # Server detection from headers
                server_header = headers.get('server', '').lower()
                x_powered_by = headers.get('x-powered-by', '').lower()
                
                # Web servers
                web_servers = {
                    'apache': ['apache', 'httpd'],
                    'nginx': ['nginx'],
                    'iis': ['microsoft-iis', 'iis'],
                    'litespeed': ['litespeed'],
                    'cloudflare': ['cloudflare'],
                    'gws': ['gws']  # Google Web Server
                }
                
                for server, indicators in web_servers.items():
                    if any(indicator in server_header for indicator in indicators):
                        technologies['web_servers'].append(f"{server} ({server_header})")
                
                progress.update(task, advance=10)
                
                # Framework detection
                frameworks = {
                    'wordpress': ['wp-content', 'wordpress'],
                    'drupal': ['drupal'],
                    'joomla': ['joomla'],
                    'laravel': ['laravel'],
                    'django': ['django'],
                    'rails': ['rails'],
                    'express': ['express'],
                    'spring': ['spring'],
                    'asp.net': ['asp.net', 'aspx'],
                    'next.js': ['next.js', '__next'],
                    'nuxt.js': ['nuxt.js'],
                    'vue.js': ['vue', 'vue.js'],
                    'react': ['react'],
                    'angular': ['angular']
                }
                
                for framework, indicators in frameworks.items():
                    if any(indicator.lower() in content.lower() for indicator in indicators):
                        technologies['frameworks'].append(framework)
                
                progress.update(task, advance=15)
                
                # JavaScript libraries
                js_libraries = {
                    'jquery': ['jquery', '$().'],
                    'react': ['react', 'reactdom'],
                    'vue': ['vue', 'new vue'],
                    'angular': ['angular', 'ng-'],
                    'bootstrap': ['bootstrap'],
                    'foundation': ['foundation'],
                    'three.js': ['three.js'],
                    'd3.js': ['d3.js']
                }
                
                for lib, indicators in js_libraries.items():
                    if any(indicator.lower() in content.lower() for indicator in indicators):
                        technologies['javascript_libraries'].append(lib)
                
                progress.update(task, advance=15)
                
                # CMS detection
                cms_patterns = {
                    'wordpress': [r'wp-content', r'wordpress'],
                    'drupal': [r'drupal', r'sites/all'],
                    'joomla': [r'joomla', r'media/jui'],
                    'magento': [r'magento', r'static/frontend'],
                    'shopify': [r'shopify'],
                    'wix': [r'wix'],
                    'squarespace': [r'squarespace']
                }
                
                for cms, patterns in cms_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            technologies['cms'].append(cms)
                            break
                
                progress.update(task, advance=10)
                
                # CDN detection
                cdn_indicators = {
                    'cloudflare': ['cloudflare', 'cf-ray'],
                    'akamai': ['akamai'],
                    'aws cloudfront': ['cloudfront'],
                    'fastly': ['fastly'],
                    'cloudflare': ['cloudflare'],
                    'maxcdn': ['maxcdn'],
                    'incapsula': ['incapsula']
                }
                
                for cdn, indicators in cdn_indicators.items():
                    if any(indicator.lower() in str(headers).lower() for indicator in indicators):
                        technologies['cdn'].append(cdn)
                
                progress.update(task, advance=10)
                
                # Security detection
                security_headers = {
                    'waf': ['waf', 'firewall'],
                    'mod_security': ['mod_security'],
                    'cloudflare_waf': ['cloudflare-waf'],
                    'akamai_ghost': ['akamai-ghost']
                }
                
                for security, indicators in security_headers.items():
                    if any(indicator.lower() in str(headers).lower() for indicator in indicators):
                        technologies['security'].append(security)
                
                progress.update(task, advance=10)
                
                # Analytics
                analytics = {
                    'google_analytics': ['google-analytics', 'ga.js'],
                    'google_tag_manager': ['googletagmanager'],
                    'facebook_pixel': ['facebook-pixel'],
                    'hotjar': ['hotjar'],
                    'matomo': ['matomo']
                }
                
                for analytic, indicators in analytics.items():
                    if any(indicator.lower() in content.lower() for indicator in indicators):
                        technologies['analytics'].append(analytic)
                
                progress.update(task, advance=10)
                
                self.results['technologies'] = technologies
                progress.update(task, completed=100)
                
            except Exception as e:
                console.print(f"❌ [red]Technology detection error: {e}[/red]")
    
    async def analyze_ssl_tls(self):
        """SSL/TLS certificate analysis"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🔐 Analyzing SSL/TLS...", total=100)
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        
                        ssl_info = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert.get('version', 'N/A'),
                            'serialNumber': cert.get('serialNumber', 'N/A'),
                            'notBefore': cert.get('notBefore', 'N/A'),
                            'notAfter': cert.get('notAfter', 'N/A'),
                            'subjectAltName': cert.get('subjectAltName', []),
                            'OCSP': cert.get('OCSP', []),
                            'caIssuers': cert.get('caIssuers', [])
                        }
                        
                        self.results['ssl_tls'] = ssl_info
                        progress.update(task, completed=100)
                        
            except Exception as e:
                console.print(f"❌ [red]SSL/TLS analysis error: {e}[/red]")
    
    async def detect_waf(self):
        """WAF detection and analysis"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🛡️ Detecting WAF...", total=100)
            
            waf_signatures = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'Akamai': ['akamai', 'akamaighost'],
                'Imperva': ['imperva', 'incapsula'],
                'AWS WAF': ['aws', 'awselb/2.0'],
                'ModSecurity': ['mod_security'],
                'Wordfence': ['wordfence'],
                'Sucuri': ['sucuri'],
                'FortiWeb': ['fortiweb'],
                'F5 BIG-IP': ['bigip', 'f5'],
                'Barracuda': ['barracuda']
            }
            
            try:
                # Test with malicious payload
                payloads = [
                    "../../etc/passwd",
                    "<script>alert('xss')</script>",
                    "' OR 1=1--",
                    "../../../etc/passwd"
                ]
                
                detected_wafs = []
                
                for payload in payloads:
                    test_url = f"http://{self.target}/?test={payload}"
                    async with self.session.get(test_url) as response:
                        headers = dict(response.headers)
                        content = await response.text()
                        
                        for waf, signatures in waf_signatures.items():
                            for signature in signatures:
                                if (signature.lower() in str(headers).lower() or 
                                    signature.lower() in content.lower()):
                                    detected_wafs.append(waf)
                                    break
                
                progress.update(task, advance=50)
                
                # Check for WAF specific patterns
                waf_patterns = {
                    'Cloudflare': [r'cf-ray', r'cloudflare'],
                    'Akamai': [r'akamai', r'x-akamai'],
                    'Imperva': [r'incapsula', r'x-iinfo']
                }
                
                for waf, patterns in waf_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, str(headers), re.IGNORECASE):
                            if waf not in detected_wafs:
                                detected_wafs.append(waf)
                
                progress.update(task, advance=50)
                
                self.results['waf'] = list(set(detected_wafs))
                progress.update(task, completed=100)
                
            except Exception as e:
                console.print(f"❌ [red]WAF detection error: {e}[/red]")
    
    async def analyze_dns(self):
        """DNS records analysis"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🌐 Analyzing DNS records...", total=100)
            
            try:
                dns_records = {}
                record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
                
                for record_type in record_types:
                    try:
                        answers = dns.resolver.resolve(self.target, record_type)
                        dns_records[record_type] = [str(rdata) for rdata in answers]
                    except:
                        dns_records[record_type] = []
                    
                    progress.update(task, advance=100/len(record_types))
                
                self.results['dns'] = dns_records
                
            except Exception as e:
                console.print(f"❌ [red]DNS analysis error: {e}[/red]")
    
    async def detect_honeypots(self):
        """Honeypot detection system"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🍯 Detecting honeypots...", total=100)
            
            honeypot_indicators = []
            
            try:
                # Check for common honeypot signatures
                honeypot_tests = [
                    # HTTP response patterns
                    ("/wp-admin/install.php", "WordPress installation"),
                    ("/phpmyadmin/", "phpMyAdmin honeypot"),
                    ("/cgi-bin/", "CGI honeypot"),
                    ("/admin/", "Admin panel honeypot"),
                    
                    # Port-based detection
                    (22, "SSH honeypot"),
                    (23, "Telnet honeypot"),
                    (1433, "MSSQL honeypot"),
                    (3306, "MySQL honeypot")
                ]
                
                for test, description in honeypot_tests:
                    if isinstance(test, int):  # Port test
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((self.target, test))
                            sock.close()
                            if result == 0:
                                honeypot_indicators.append(f"{description} (Port {test})")
                        except:
                            pass
                    else:  # URL test
                        try:
                            async with self.session.get(f"http://{self.target}{test}") as response:
                                if response.status == 200:
                                    honeypot_indicators.append(description)
                        except:
                            pass
                    
                    progress.update(task, advance=100/len(honeypot_tests))
                
                self.results['honeypots'] = honeypot_indicators
                
            except Exception as e:
                console.print(f"❌ [red]Honeypot detection error: {e}[/red]")
    
    async def analyze_http_headers(self):
        """Detailed HTTP headers analysis"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("📋 Analyzing HTTP headers...", total=100)
            
            try:
                async with self.session.get(f"http://{self.target}") as response:
                    headers = dict(response.headers)
                    
                    header_analysis = {
                        'security_headers': {},
                        'server_info': {},
                        'cache_headers': {},
                        'content_headers': {},
                        'custom_headers': {}
                    }
                    
                    # Security headers
                    security_headers_list = [
                        'content-security-policy', 'x-frame-options', 'x-content-type-options',
                        'x-xss-protection', 'strict-transport-security', 'referrer-policy'
                    ]
                    
                    for header in security_headers_list:
                        if header in headers:
                            header_analysis['security_headers'][header] = headers[header]
                    
                    # Server information
                    server_headers = ['server', 'x-powered-by', 'x-aspnet-version']
                    for header in server_headers:
                        if header in headers:
                            header_analysis['server_info'][header] = headers[header]
                    
                    progress.update(task, completed=100)
                    self.results['http_headers'] = header_analysis
                
            except Exception as e:
                console.print(f"❌ [red]HTTP headers analysis error: {e}[/red]")
    
    async def comprehensive_scan(self):
        """Run all scans comprehensively"""
        console.print(Panel.fit(
            f"[bold blue]Beagle Scanner[/bold blue]\n"
            f"[green]Author: CEO[/green] | [yellow]Version: 1.1[/yellow]\n"
            f"Target: [bold red]{self.target}[/bold red]\n"
            f"Tor Proxy: {'[green]Enabled[/green]' if self.use_tor else '[red]Disabled[/red]'}",
            title="🚀 Starting Advanced Scan"
        ))
        
        await self._create_session()
        
        # Run all scans concurrently
        tasks = [
            self.scan_ports(),
            self.detect_technologies(),
            self.analyze_ssl_tls(),
            self.detect_waf(),
            self.analyze_dns(),
            self.detect_honeypots(),
            self.analyze_http_headers()
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        await self.session.close()
        
        return self.results

class BeagleDisplay:
    """Advanced results display using Rich"""
    
    @staticmethod
    def show_results(results: Dict):
        """Display all scan results in beautiful format"""
        
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header
        layout["header"].update(
            Panel.fit(
                "[bold blue]Beagle[/bold blue] - [green]Advanced Web Reconnaissance Tool[/green] | "
                "[yellow]Author: CEO[/yellow] | [red]Version: 1.1[/red]",
                style="bold white"
            )
        )
        
        # Body with tabs-like structure
        body_layout = Layout()
        body_layout.split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        # Left panel - Technical details
        left_content = []
        
        # Ports table
        if 'ports' in results:
            ports_table = Table(title="🔍 Open Ports & Services", show_header=True)
            ports_table.add_column("Port", style="cyan")
            ports_table.add_column("Service", style="green")
            ports_table.add_column("State", style="yellow")
            
            for port_info in results['ports']:
                ports_table.add_row(
                    str(port_info['port']),
                    port_info['service'],
                    port_info['state']
                )
            left_content.append(ports_table)
        
        # Technologies
        if 'technologies' in results:
            tech_tree = Tree("🔧 Detected Technologies")
            
            for category, items in results['technologies'].items():
                if items:
                    category_branch = tech_tree.add(f"[bold]{category.replace('_', ' ').title()}[/bold]")
                    for item in items:
                        category_branch.add(f"[green]✓[/green] {item}")
            
            left_content.append(tech_tree)
        
        # Right panel - Security & Analysis
        right_content = []
        
        # WAF Detection
        if 'waf' in results:
            waf_panel = Panel(
                "\n".join([f"🛡️  {waf}" for waf in results['waf']]) if results['waf'] else "❌ No WAF detected",
                title="WAF Protection",
                border_style="red" if results['waf'] else "green"
            )
            right_content.append(waf_panel)
        
        # Honeypots
        if 'honeypots' in results:
            honeypot_panel = Panel(
                "\n".join([f"🍯 {honeypot}" for honeypot in results['honeypots']]) if results['honeypots'] else "✅ No honeypots detected",
                title="Honeypot Detection",
                border_style="red" if results['honeypots'] else "green"
            )
            right_content.append(honeypot_panel)
        
        # SSL/TLS Info
        if 'ssl_tls' in results:
            ssl_info = results['ssl_tls']
            ssl_content = f"""
            [bold]Subject:[/bold] {ssl_info.get('subject', {}).get('commonName', 'N/A')}
            [bold]Issuer:[/bold] {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}
            [bold]Valid Until:[/bold] {ssl_info.get('notAfter', 'N/A')}
            """
            ssl_panel = Panel(ssl_content, title="🔐 SSL/TLS Certificate", border_style="yellow")
            right_content.append(ssl_panel)
        
        # DNS Records
        if 'dns' in results:
            dns_tree = Tree("🌐 DNS Records")
            for record_type, records in results['dns'].items():
                if records:
                    record_branch = dns_tree.add(f"[bold]{record_type}[/bold]")
                    for record in records:
                        record_branch.add(f"[cyan]{record}[/cyan]")
            right_content.append(dns_tree)
        
        # Combine left and right content
        left_layout = Layout()
        for item in left_content:
            left_layout.split_row(Layout(item))
        
        right_layout = Layout()
        for item in right_content:
            right_layout.split_row(Layout(item))
        
        body_layout["left"].update(left_layout)
        body_layout["right"].update(right_layout)
        layout["body"].update(body_layout)
        
        # Footer
        layout["footer"].update(
            Panel.fit(
                "[bold green]Scan completed successfully![/bold green] | "
                "[yellow]Use results responsibly[/yellow]",
                style="bold white"
            )
        )
        
        console.print(layout)
        
        # Detailed vulnerability assessment
        BeagleDisplay._show_vulnerability_assessment(results)
    
    @staticmethod
    def _show_vulnerability_assessment(results: Dict):
        """Show vulnerability assessment based on findings"""
        
        console.print("\n")
        console.print(Panel.fit(
            "[bold red]VULNERABILITY ASSESSMENT & PENETRATION TESTING SUMMARY[/bold red]",
            style="bold red"
        ))
        
        # DDoS Attack Vector Analysis
        ddos_analysis = Table(title="🔄 DDoS Attack Vectors Analysis")
        ddos_analysis.add_column("Attack Type", style="cyan")
        ddos_analysis.add_column("Feasibility", style="yellow")
        ddos_analysis.add_column("Potential Impact", style="red")
        ddos_analysis.add_column("Protection Status", style="green")
        
        ddos_analysis.add_row(
            "HTTP Flood",
            "High" if any(p['port'] in [80, 443, 8080, 8443] for p in results.get('ports', [])) else "Medium",
            "Critical",
            "Protected" if results.get('waf') else "Vulnerable"
        )
        
        ddos_analysis.add_row(
            "SYN Flood",
            "High",
            "Critical", 
            "Unknown"
        )
        
        ddos_analysis.add_row(
            "DNS Amplification",
            "Medium" if any('cloudflare' in cdn.lower() for cdn in results.get('technologies', {}).get('cdn', [])) else "High",
            "High",
            "Protected" if any('cloudflare' in cdn.lower() for cdn in results.get('technologies', {}).get('cdn', [])) else "Vulnerable"
        )
        
        console.print(ddos_analysis)
        
        # Security Recommendations
        security_table = Table(title="🛡️ Security Recommendations")
        security_table.add_column("Issue", style="red")
        security_table.add_column("Risk Level", style="yellow")
        security_table.add_column("Recommendation", style="green")
        
        if not results.get('waf'):
            security_table.add_row(
                "No WAF Detected",
                "High",
                "Implement Cloudflare or similar WAF protection"
            )
        
        if any('wordpress' in cms.lower() for cms in results.get('technologies', {}).get('cms', [])):
            security_table.add_row(
                "WordPress Detected",
                "Medium",
                "Keep plugins/themes updated, use security plugins"
            )
        
        if any(port['port'] == 22 for port in results.get('ports', [])):
            security_table.add_row(
                "SSH Port Open",
                "Medium", 
                "Use key-based authentication, change default port"
            )
        
        console.print(security_table)

async def main():
    """Main function"""
    if len(sys.argv) < 2:
        console.print("Usage: python beagle.py <target> [--tor]")
        console.print("Example: python beagle.py example.com --tor")
        sys.exit(1)
    
    target = sys.argv[1]
    use_tor = "--tor" in sys.argv
    
    # Validate target
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        console.print("❌ [red]Invalid target format[/red]")
        sys.exit(1)
    
    try:
        # Initialize scanner
        scanner = BeagleScanner(target, use_tor)
        
        # Run comprehensive scan
        results = await scanner.comprehensive_scan()
        
        # Display results
        BeagleDisplay.show_results(results)
        
    except KeyboardInterrupt:
        console.print("\n❌ [yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"❌ [red]Unexpected error: {e}[/red]")

if __name__ == "__main__":
    # Check dependencies
    try:
        import rich
        import aiohttp
        import beautifulsoup4
        import python-nmap
        import dnspython
        import stem
        import fake_useragent
        import socks
    except ImportError as e:
        console.print(f"❌ [red]Missing dependency: {e}[/red]")
        console.print("📦 Install all dependencies: pip install rich aiohttp beautifulsoup4 python-nmap dnspython stem fake_useragent PySocks")
        sys.exit(1)
    
    asyncio.run(main())
