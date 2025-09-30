#!/usr/bin/env python3
"""
Beagle - Author CEO
Advanced Technology & Security Detection Tool
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import re
import hashlib
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import nmap
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from bs4 import BeautifulSoup
import threading
from datetime import datetime
import time
import subprocess
import os
from typing import Dict, List, Any, Optional

console = Console()

class BeagleScanner:
    def __init__(self, target: str, use_tor: bool = False, timeout: int = 30):
        self.target = self.normalize_target(target)
        self.use_tor = use_tor
        self.timeout = timeout
        self.session = None
        self.results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'technologies': {},
            'security': {},
            'network': {},
            'fingerprints': {},
            'versions': {},
            'ports': {}
        }
        
        # Enhanced signature database
        self.signatures = self.load_enhanced_signatures()
        
    def normalize_target(self, target: str) -> str:
        """Normalize target URL"""
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
    
    def load_enhanced_signatures(self) -> Dict[str, Any]:
        """Load comprehensive detection signatures"""
        return {
            'web_frameworks': {
                'React': {'patterns': [r'react@([\d.]+)', r'React v([\d.]+)'], 'files': ['static/js/main.*.js']},
                'Angular': {'patterns': [r'angular@([\d.]+)', r'ng-version="([\d.]+)"']},
                'Vue.js': {'patterns': [r'vue@([\d.]+)', r'Vue\.version="([\d.]+)"']},
                'Django': {'patterns': [r'csrfmiddlewaretoken', r'Django/([\d.]+)']},
                'Laravel': {'patterns': [r'laravel_session', r'X-Powered-By: Laravel']},
                'Express': {'patterns': [r'X-Powered-By: Express']},
                'Ruby on Rails': {'patterns': [r'rails', r'X-Runtime: Ruby']},
                'Spring Boot': {'patterns': [r'spring-boot', r'X-Application-Context']},
            },
            'cms': {
                'WordPress': {
                    'patterns': [r'wp-json', r'wp-includes', r'wp-admin', r'wordpress@([\d.]+)'],
                    'files': ['wp-config.php', 'xmlrpc.php'],
                    'meta': ['generator', 'WordPress']
                },
                'Joomla': {'patterns': [r'joomla', r'Joomla!']},
                'Drupal': {'patterns': [r'drupal', r'Drupal ([\\d.]+)']},
                'Magento': {'patterns': [r'magento', r'Mage.Cookies']},
            },
            'security': {
                'WAF': {
                    'Cloudflare': {'headers': ['server', 'cf-ray'], 'patterns': [r'cloudflare']},
                    'Akamai': {'headers': ['server'], 'patterns': [r'akamai']},
                    'Imperva': {'headers': ['server'], 'patterns': [r'incapsula']},
                },
                'Firewall': {
                    'ModSecurity': {'headers': ['server'], 'patterns': [r'mod_security']},
                    'Wordfence': {'patterns': [r'wordfence']},
                }
            },
            'servers': {
                'nginx': {'headers': ['server'], 'patterns': [r'nginx/([\\d.]+)']},
                'Apache': {'headers': ['server'], 'patterns': [r'Apache/([\\d.]+)']},
                'IIS': {'headers': ['server'], 'patterns': [r'Microsoft-IIS/([\\d.]+)']},
            },
            'analytics': {
                'Google Analytics': {'patterns': [r'ga.js', r'analytics.js', r'gtag.js']},
                'Google Tag Manager': {'patterns': [r'googletagmanager.com']},
            }
        }

    async def init_session(self):
        """Initialize HTTP session with Tor support if needed"""
        if self.use_tor:
            connector = aiohttp.TCPConnector()
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        else:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )

    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

    async def fetch_url(self, url: str) -> Optional[Dict]:
        """Fetch URL with comprehensive response data"""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                return {
                    'url': str(response.url),
                    'status': response.status,
                    'headers': headers,
                    'content': content,
                    'cookies': dict(response.cookies),
                    'history': [str(r.url) for r in response.history]
                }
        except Exception as e:
            console.print(f"[red]Error fetching {url}: {str(e)}[/red]")
            return None

    async def detect_technologies(self, response: Dict) -> Dict:
        """Advanced technology detection"""
        technologies = {}
        content = response.get('content', '')
        headers = response.get('headers', {})
        
        # HTML Meta Tags analysis
        if 'text/html' in headers.get('content-type', ''):
            soup = BeautifulSoup(content, 'html.parser')
            
            # Meta tags analysis
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                content = meta.get('content', '')
                if name and content:
                    meta_tags[name.lower()] = content
            
            technologies['meta_tags'] = meta_tags
            
            # Script analysis
            scripts = []
            for script in soup.find_all('script'):
                src = script.get('src', '')
                content = script.string
                if src:
                    scripts.append({'src': src, 'type': 'external'})
                elif content:
                    scripts.append({'content_preview': content[:100], 'type': 'inline'})
            
            technologies['scripts'] = scripts
            
            # CSS analysis
            css_links = []
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href', '')
                if href:
                    css_links.append(href)
            
            technologies['css'] = css_links

        # Header-based detection
        for tech_type, techs in self.signatures.items():
            for tech_name, patterns in techs.items():
                # Check headers
                for header_name, header_value in headers.items():
                    for pattern in patterns.get('patterns', []):
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.groups() else 'unknown'
                            technologies[tech_name] = {
                                'type': tech_type,
                                'version': version,
                                'source': f'header:{header_name}',
                                'confidence': 'high'
                            }
                
                # Check content
                for pattern in patterns.get('patterns', []):
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else 'unknown'
                        technologies[tech_name] = {
                            'type': tech_type,
                            'version': version,
                            'source': 'content',
                            'confidence': 'medium'
                        }

        return technologies

    async def port_scan(self, ports: List[int] = None) -> Dict:
        """Advanced port scanning with service detection"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]
        
        domain = urlparse(self.target).hostname
        
        try:
            nm = nmap.PortScanner()
            port_str = ','.join(map(str, ports))
            
            console.print(f"[yellow]Scanning ports {port_str} on {domain}...[/yellow]")
            
            nm.scan(hosts=domain, ports=port_str, arguments='-sV -sS -T4')
            
            port_results = {}
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        port_results[port] = {
                            'state': service['state'],
                            'service': service['name'],
                            'version': service['version'],
                            'product': service['product'],
                            'extrainfo': service['extrainfo']
                        }
            
            return port_results
        except Exception as e:
            console.print(f"[red]Port scan error: {str(e)}[/red]")
            return {}

    async def dns_analysis(self, domain: str) -> Dict:
        """Comprehensive DNS analysis"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                records[record_type] = f"Error: {str(e)}"
        
        return records

    async def ssl_certificate_analysis(self, domain: str) -> Dict:
        """TLS/SSL certificate inspection"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', []),
                    }
        except Exception as e:
            return {'error': str(e)}

    async def comprehensive_scan(self):
        """Run comprehensive scan with all modules"""
        await self.init_session()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            
            tasks = [
                progress.add_task("[cyan]Fetching target...", total=1),
                progress.add_task("[green]Detecting technologies...", total=1),
                progress.add_task("[blue]Port scanning...", total=1),
                progress.add_task("[magenta]DNS analysis...", total=1),
                progress.add_task("[yellow]SSL analysis...", total=1),
            ]
            
            # Fetch target
            response = await self.fetch_url(self.target)
            progress.update(tasks[0], advance=1)
            
            if response:
                # Technology detection
                self.results['technologies'] = await self.detect_technologies(response)
                progress.update(tasks[1], advance=1)
                
                # Store response data
                self.results['response'] = {
                    'status': response['status'],
                    'headers': response['headers'],
                    'cookies': response['cookies']
                }
            
            # Network scans
            domain = urlparse(self.target).hostname
            
            # Port scanning
            self.results['ports'] = await self.port_scan()
            progress.update(tasks[2], advance=1)
            
            # DNS analysis
            self.results['dns'] = await self.dns_analysis(domain)
            progress.update(tasks[3], advance=1)
            
            # SSL analysis
            self.results['ssl'] = await self.ssl_certificate_analysis(domain)
            progress.update(tasks[4], advance=1)
        
        await self.close_session()

    def display_results(self):
        """Display beautiful results in terminal"""
        console.print()
        console.print(Panel.fit(
            "[bold cyan]🐕 Beagle - Author CEO[/bold cyan]\n"
            "[bold yellow]Advanced Technology & Security Detection Tool[/bold yellow]",
            border_style="cyan"
        ))
        
        # Target Information
        target_table = Table(show_header=True, header_style="bold magenta")
        target_table.add_column("Property", style="cyan")
        target_table.add_column("Value", style="white")
        
        target_table.add_row("Target", self.results['target'])
        target_table.add_row("Scan Time", self.results['timestamp'])
        target_table.add_row("Status Code", str(self.results.get('response', {}).get('status', 'N/A')))
        
        console.print(Panel(target_table, title="📡 Target Information", border_style="green"))

        # Technologies Detected
        if self.results['technologies']:
            tech_table = Table(show_header=True, header_style="bold blue")
            tech_table.add_column("Technology", style="cyan")
            tech_table.add_column("Type", style="green")
            tech_table.add_column("Version", style="yellow")
            tech_table.add_column("Confidence", style="white")
            tech_table.add_column("Source", style="magenta")
            
            for tech, info in self.results['technologies'].items():
                if isinstance(info, dict):
                    tech_table.add_row(
                        tech,
                        info.get('type', 'unknown'),
                        info.get('version', 'unknown'),
                        info.get('confidence', 'unknown'),
                        info.get('source', 'unknown')
                    )
            
            console.print(Panel(tech_table, title="🔧 Technologies Detected", border_style="blue"))

        # Port Scan Results
        if self.results['ports']:
            port_table = Table(show_header=True, header_style="bold red")
            port_table.add_column("Port", style="cyan")
            port_table.add_column("State", style="green")
            port_table.add_column("Service", style="yellow")
            port_table.add_column("Version", style="white")
            port_table.add_column("Product", style="magenta")
            
            for port, info in self.results['ports'].items():
                port_table.add_row(
                    str(port),
                    info.get('state', 'unknown'),
                    info.get('service', 'unknown'),
                    info.get('version', 'unknown'),
                    info.get('product', 'unknown')
                )
            
            console.print(Panel(port_table, title="🔍 Port Scan Results", border_style="red"))

        # DNS Records
        if self.results['dns']:
            dns_table = Table(show_header=True, header_style="bold yellow")
            dns_table.add_column("Record Type", style="cyan")
            dns_table.add_column("Values", style="white")
            
            for record_type, values in self.results['dns'].items():
                if isinstance(values, list):
                    dns_table.add_row(record_type, '\n'.join(values))
                else:
                    dns_table.add_row(record_type, str(values))
            
            console.print(Panel(dns_table, title="🌐 DNS Analysis", border_style="yellow"))

        # SSL Certificate Info
        if self.results['ssl'] and 'error' not in self.results['ssl']:
            ssl_table = Table(show_header=True, header_style="bold green")
            ssl_table.add_column("Property", style="cyan")
            ssl_table.add_column("Value", style="white")
            
            ssl_info = self.results['ssl']
            ssl_table.add_row("Subject", str(ssl_info.get('subject', {})))
            ssl_table.add_row("Issuer", str(ssl_info.get('issuer', {})))
            ssl_table.add_row("Valid From", ssl_info.get('notBefore', 'N/A'))
            ssl_table.add_row("Valid Until", ssl_info.get('notAfter', 'N/A'))
            
            console.print(Panel(ssl_table, title="🔒 SSL Certificate", border_style="green"))

        # Response Headers
        if self.results.get('response', {}).get('headers'):
            headers = self.results['response']['headers']
            headers_table = Table(show_header=True, header_style="bold magenta")
            headers_table.add_column("Header", style="cyan")
            headers_table.add_column("Value", style="white")
            
            for header, value in list(headers.items())[:10]:  # Show first 10
                headers_table.add_row(header, str(value))
            
            console.print(Panel(headers_table, title="📋 HTTP Headers (Sample)", border_style="magenta"))

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Beagle - Advanced Technology Detection Tool')
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('--tor', action='store_true', help='Use Tor for anonymity')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--ports', help='Custom ports to scan (comma-separated)')
    
    args = parser.parse_args()
    
    # Parse custom ports
    custom_ports = None
    if args.ports:
        custom_ports = [int(port.strip()) for port in args.ports.split(',')]
    
    # Create and run scanner
    scanner = BeagleScanner(
        target=args.target,
        use_tor=args.tor,
        timeout=args.timeout
    )
    
    try:
        # Run comprehensive scan
        asyncio.run(scanner.comprehensive_scan())
        
        # Display results
        scanner.display_results()
        
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
    except Exception as e:
        console.print(f"[red]Error during scan: {str(e)}[/red]")
    finally:
        # Ensure session is closed
        asyncio.run(scanner.close_session())

if __name__ == "__main__":
    main()
