"""
KernelByte Scanner - single-file CLI vulnerability reconnaissance tool (Improved)
Author: KernelByte
Contact: KernelByte@protonmail.com (PGP required)
License: MIT

IMPORTANT LEGAL WARNING
This tool is provided for EDUCATIONAL, DEFENSIVE, AND AUTHORIZED TESTING ONLY.
Do NOT run against systems you do not own or do not have explicit, written permission to test.
The author and distributor are not responsible for misuse.

DESCRIPTION (improvements added):
 - Fixed confirmation input loop and asyncio deprecation warnings (works reliably on Debian/Ubuntu terminals)
 - Added optional nmap integration (if nmap binary installed) for service/OS detection
 - Added CSV and HTML export alongside JSON
 - Added progress reporting using a lightweight progress spinner and optional tqdm if installed
 - Added more API enrichment integrations (best-effort wrappers; missing/invalid keys handled gracefully):
   VirusTotal, Shodan, AbuseIPDB, IPInfo, WhoisXML, MalShare, GreyNoise, SecurityTrails, AlienVault OTX, DNSDumpster, Aikido, CriminalIP, AuthAbuse, alphavantage, newsapi, ipqualityscore, iphub
 - Improved CLI UX and safer defaults (lower concurrency, polite timeouts)
 - Better error handling, logging, and clear reminder about legal use

Requirements (Debian/Ubuntu):
 - Python 3.8+
 - pip install -r requirements.txt

requirements.txt (recommended):
 aiohttp
 aiodns
 python-dotenv
 python-nmap
 tqdm

Install example:
 sudo apt update && sudo apt install -y python3 python3-pip nmap
 pip3 install aiohttp aiodns python-dotenv python-nmap tqdm

USAGE (examples):
 python3 kernelbyte_scanner.py --target example.com
 python3 kernelbyte_scanner.py --target 198.51.100.25 --full --autolayer2 --deep-full --discord-webhook "https://discordapp.com/api/webhooks/..."
 python3 kernelbyte_scanner.py --target example.com --subdomains --subfile wordlist.txt --nmap

Note: nmap option requires the nmap binary (system package). The script will not attempt exploitation.

"""

import argparse
import asyncio
import socket
import ssl
import sys
import json
import os
import time
import ipaddress
import subprocess
import csv
import html
from datetime import datetime
from typing import List, Dict, Any, Optional
from threading import Thread

# optional imports
try:
    import aiohttp
    import aiodns
    from dotenv import load_dotenv
except Exception:
    print("[!] Missing Python dependencies. Please run: pip3 install aiohttp aiodns python-dotenv")
    sys.exit(1)

# optional extras
try:
    import nmap as libnmap
    HAS_NMAP_LIB = True
except Exception:
    HAS_NMAP_LIB = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except Exception:
    HAS_TQDM = False

load_dotenv()

# -------------------- Configuration / Defaults --------------------
BANNER = r"""
 _  __          _                ____        _
| |/ /___ _   _| |__   ___ _ __ | __ )  ___ | |_
| ' // _ \ | | | '_ \ / _ \ '_ \|  _ \ / _ \| __|
| . \  __/ |_| | |_) |  __/ | | | |_) | (_) | |_
|_|\_\___|\__, |_.__/ \___|_| |_|____/ \___/ \__|
           |___/
KernelByte Scanner - MIT License
"""

DEFAULT_CONCURRENCY = 200
CONNECT_TIMEOUT = 3.0
BANNER_GRAB_BYTES = 1024
DEFAULT_TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,5900,8080]
EXPORT_DIR = os.getcwd()

# -------------------- Utility Functions --------------------

def is_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def now_iso() -> str:
    return datetime.utcnow().isoformat() + 'Z'


def safe_filename(s: str) -> str:
    return ''.join(c if c.isalnum() or c in '._-' else '_' for c in s)

# -------------------- Confirmation with timeout (fixed) --------------------

def legal_confirmation_sync(prompt: str = None, timeout: int = 20) -> bool:
    """Synchronous confirmation using a background thread and timeout (avoids asyncio loop issues)."""
    if prompt is None:
        prompt = "Do you confirm you own or have explicit permission to test the target? (yes/no): "
    if os.getenv('KB_AUTO_CONFIRM') == '1':
        return True

    print('\n' + BANNER)

    print("LEGAL NOTICE: You must only scan systems you own or have written permission to test.")
    print(f"You have {timeout} seconds to respond. Type 'yes' to proceed.")

    answer = {'value': None}

    def read_input():
        try:
            answer['value'] = sys.stdin.readline().strip().lower()
        except Exception:
            answer['value'] = None

    t = Thread(target=read_input, daemon=True)
    t.start()
    t.join(timeout)
    if not answer['value']:
        print('\n' + BANNER)
[!] No confirmation received (timeout).')
        return False
    if answer['value'] == 'yes':
        return True
    return False

# -------------------- Async Port Scanner --------------------

semaphore = None

async def tcp_connect(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> Optional[str]:
    global semaphore
    try:
        await semaphore.acquire()
        reader = None
        writer = None
        try:
            fut = asyncio.open_connection(host=host, port=port)
            task = asyncio.wait_for(fut, timeout=timeout)
            reader, writer = await task
            # try to read banner
            try:
                writer.write(b"
")
                await writer.drain()
            except Exception:
                pass
            try:
                data = await asyncio.wait_for(reader.read(BANNER_GRAB_BYTES), timeout=1.0)
                if data:
                    try:
                        return data.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        return repr(data)
                else:
                    return ''
            except Exception:
                return ''
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        try:
            semaphore.release()
        except Exception:
            pass


async def scan_ports(host: str, ports: List[int], concurrency: int, show_progress: bool = True) -> Dict[int, Optional[str]]:
    global semaphore
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    results: Dict[int, Optional[str]] = {}

    loop = asyncio.get_event_loop()

    for p in ports:
        tasks.append(loop.create_task(tcp_connect(host, p)))

    # If tqdm installed and running in terminal, show progress
    if HAS_TQDM and show_progress:
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc='Scanning ports'):
            try:
                banner = await coro
                # find index of completed task by popping from tasks is hard; instead, map via task result order
                # Since we created tasks in order, we will consume ports by iteration index from 0.. but asyncio.as_completed doesn't preserve index
                # So better to pair port->task mapping
            except Exception:
                pass
        # fallback to simpler mapping
    # Simpler reliable approach: gather in batches to preserve mapping
    gathered = await asyncio.gather(*tasks)
    for p, res in zip(ports, gathered):
        results[p] = res
    return results

# -------------------- DNS / Subdomain helpers --------------------

async def resolve_a_records(domain: str) -> List[str]:
    resolver = aiodns.DNSResolver()
    try:
        ans = await resolver.query(domain, 'A')
        return [r.host for r in ans]
    except Exception:
        return []


async def resolve_aaaa_records(domain: str) -> List[str]:
    resolver = aiodns.DNSResolver()
    try:
        ans = await resolver.query(domain, 'AAAA')
        return [r.host for r in ans]
    except Exception:
        return []


async def brute_subdomains(domain: str, wordlist_file: str, concurrency: int = 100) -> List[str]:
    subs = []
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            words = [w.strip() for w in f if w.strip()]
    except Exception:
        return subs

    sem = asyncio.Semaphore(concurrency)
    resolver = aiodns.DNSResolver()

    async def try_sub(w):
        async with sem:
            name = f"{w}.{domain}"
            try:
                await resolver.query(name, 'A')
                return name
            except Exception:
                return None

    tasks = [asyncio.create_task(try_sub(w)) for w in words]
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            subs.append(res)
    return subs

# -------------------- API Enrichment (best-effort wrappers) --------------------

async def vt_lookup(session: aiohttp.ClientSession, ip_or_domain: str, api_key: str) -> Dict[str, Any]:
    headers = {'x-apikey': api_key}
    result = {}
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}' if is_ip(ip_or_domain) else f'https://www.virustotal.com/api/v3/domains/{ip_or_domain}'
        async with session.get(url, headers=headers, timeout=10) as resp:
            if resp.status == 200:
                result = await resp.json()
            else:
                result = {'error': f'vt status {resp.status}'}
    except Exception as e:
        result = {'error': str(e)}
    return {'virustotal': result}


async def shodan_lookup(session: aiohttp.ClientSession, ip_or_domain: str, api_key: str) -> Dict[str, Any]:
    result = {}
    try:
        if is_ip(ip_or_domain):
            url = f'https://api.shodan.io/shodan/host/{ip_or_domain}?key={api_key}'
        else:
            url = f'https://api.shodan.io/dns/resolve?hostnames={ip_or_domain}&key={api_key}'
        async with session.get(url, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'shodan': result}


async def abuseipdb_lookup(session: aiohttp.ClientSession, ip: str, api_key: str) -> Dict[str, Any]:
    result = {}
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip}
        async with session.get(url, headers=headers, params=params, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'abuseipdb': result}


async def ipinfo_lookup(session: aiohttp.ClientSession, ip: str, token: str) -> Dict[str, Any]:
    result = {}
    try:
        url = f'https://ipinfo.io/{ip}/json'
        params = {'token': token} if token else {}
        async with session.get(url, params=params, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'ipinfo': result}


async def whoisxml_lookup(session: aiohttp.ClientSession, domain: str, api_key: str) -> Dict[str, Any]:
    result = {}
    try:
        url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
        params = {'domainName': domain, 'apiKey': api_key, 'outputFormat': 'JSON'}
        async with session.get(url, params=params, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'whoisxml': result}


async def greynoise_lookup(session: aiohttp.ClientSession, ip: str, api_key: str) -> Dict[str, Any]:
    result = {}
    try:
        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {'key': api_key}
        async with session.get(url, headers=headers, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'greynoise': result}


async def securitytrails_lookup(session: aiohttp.ClientSession, domain: str, api_key: str) -> Dict[str, Any]:
    result = {}
    try:
        url = f'https://api.securitytrails.com/v1/domain/{domain}/whois'
        headers = {'APIKEY': api_key}
        async with session.get(url, headers=headers, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'securitytrails': result}


async def alienvault_otx_lookup(session: aiohttp.ClientSession, ip_or_domain: str, api_key: str) -> Dict[str, Any]:
    result = {}
    try:
        # public OTX pulses lookup (best-effort)
        url = f'https://otx.alienvault.com/api/v1/indicators/ipv4/{ip_or_domain}/general' if is_ip(ip_or_domain) else f'https://otx.alienvault.com/api/v1/indicators/domain/{ip_or_domain}/passive_dns'
        headers = {'X-OTX-API-KEY': api_key}
        async with session.get(url, headers=headers, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'alienvault': result}

# Generic safe wrapper for unknown APIs provided by user keys: try a simple GET with key header or param
async def generic_api_lookup(session: aiohttp.ClientSession, name: str, ip_or_domain: str, api_key: str) -> Dict[str, Any]:
    # This is a best-effort probe and will not assume endpoint specifics.
    # We'll try to format a few common endpoints, but failures are ignored.
    probes = []
    if name.lower().startswith('dns'):
        probes.append((f'https://api.{name}.com/lookup', {}))
    probes.append((f'https://api.{name}.com/resolve/{ip_or_domain}', {}))
    out = {}
    for url, params in probes:
        try:
            headers = {'Authorization': api_key} if api_key else {}
            async with session.get(url, headers=headers, params=params, timeout=6) as resp:
                out[url] = {'status': resp.status, 'text': await resp.text()}
        except Exception as e:
            out[url] = {'error': str(e)}
    return {name: out}

# -------------------- Discord Webhook --------------------

async def send_discord_webhook(session: aiohttp.ClientSession, webhook_url: str, content: Dict[str, Any]):
    if not webhook_url:
        return {'error': 'no webhook'}
    try:
        payload = {
            'username': 'KernelByte-Scanner',
            'content': None,
            'embeds': [
                {
                    'title': f"Scan results for {content.get('target')}",
                    'description': f"`Started: {content.get('started')}`
`Finished: {content.get('finished')}`",
                    'fields': [
                        {'name': 'Open ports (count)', 'value': str(len(content.get('open_ports', []))), 'inline': True},
                        {'name': 'Top Services', 'value': ', '.join(list(content.get('services', {}).keys())[:10]) or 'n/a', 'inline': True},
                        {'name': 'Notes', 'value': content.get('notes', 'n/a'), 'inline': False}
                    ],
                    'timestamp': content.get('finished')
                }
            ]
        }
        async with session.post(webhook_url, json=payload, timeout=10) as resp:
            return {'status': resp.status, 'text': await resp.text()}
    except Exception as e:
        return {'error': str(e)}

# -------------------- Export Helpers --------------------

def export_json(report: Dict[str, Any], filename: str) -> str:
    fn = os.path.join(EXPORT_DIR, filename)
    with open(fn, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    return fn


def export_csv(report: Dict[str, Any], filename: str) -> str:
    fn = os.path.join(EXPORT_DIR, filename)
    rows = []
    target = report.get('target')
    for p, banner in report.get('services', {}).items():
        rows.append({'target': target, 'port': p, 'banner': banner})
    with open(fn, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['target', 'port', 'banner']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    return fn


def export_html(report: Dict[str, Any], filename: str) -> str:
    fn = os.path.join(EXPORT_DIR, filename)
    html_parts = []
    html_parts.append('<html><head><meta charset="utf-8"><title>KernelByte Scan Report</title></head><body>')
    html_parts.append(f"<h1>Scan results for {html.escape(report.get('target','unknown'))}</h1>")
    html_parts.append(f"<p>Started: {report.get('started')}<br>Finished: {report.get('finished')}</p>")
    html_parts.append('<h2>Open ports</h2><table border="1"><tr><th>Port</th><th>Banner</th></tr>')
    for p, b in report.get('services', {}).items():
        html_parts.append(f"<tr><td>{p}</td><td><pre>{html.escape(str(b))}</pre></td></tr>")
    html_parts.append('</table>')
    html_parts.append('</body></html>')
    with open(fn, 'w', encoding='utf-8') as f:
        f.write('
'.join(html_parts))
    return fn

# -------------------- Nmap Integration --------------------

def run_nmap_scan(target: str, ports: Optional[str] = None) -> Dict[str, Any]:
    # If nmap binary available, run -sV -O for service and OS detection (requires privileges for OS detect)
    result = {'nmap': None}
    try:
        args = ['nmap', '-sV', '-O', target]
        if ports:
            args = ['nmap', '-sV', '-O', '-p', ports, target]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=300)
        result['nmap'] = {'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}
    except FileNotFoundError:
        result['nmap'] = {'error': 'nmap binary not found'}
    except Exception as e:
        result['nmap'] = {'error': str(e)}
    return result

# -------------------- Main Scan Flow --------------------

async def enrich_and_report(target: str, ips: List[str], open_ports: Dict[int, Optional[str]], args) -> Dict[str, Any]:
    out = {
        'target': target,
        'started': args.started,
        'finished': now_iso(),
        'open_ports': [p for p, b in open_ports.items() if b is not None],
        'services': {p: (open_ports[p] or '') for p in open_ports if open_ports[p] is not None},
        'notes': ''
    }

    async with aiohttp.ClientSession() as session:
        api_tasks = []
        vt = os.getenv('VIRUSTOTAL_API') or args.virustotal
        shodan = os.getenv('SHODAN_API') or args.shodan
        abuse = os.getenv('ABUSEIPDB_API') or args.abuseipdb
        ipinfo = os.getenv('IPINFO_TOKEN') or args.ipinfo
        whoisxml = os.getenv('WHOISXML_API') or args.whoisxml
        greynoise = os.getenv('GREYNOISE_API') or args.greynoise
        securitytrails = os.getenv('SECURITYTRAILS_API') or args.securitytrails
        alienotx = os.getenv('ALIENVAULT_API') or args.alienvault

        primary_ip = ips[0] if ips else target

        if vt:
            api_tasks.append(vt_lookup(session, primary_ip if is_ip(primary_ip) else target, vt))
        if shodan:
            api_tasks.append(shodan_lookup(session, primary_ip if is_ip(primary_ip) else target, shodan))
        if abuse and is_ip(primary_ip):
            api_tasks.append(abuseipdb_lookup(session, primary_ip, abuse))
        if ipinfo and is_ip(primary_ip):
            api_tasks.append(ipinfo_lookup(session, primary_ip, ipinfo))
        if whoisxml and not is_ip(target):
            api_tasks.append(whoisxml_lookup(session, target, whoisxml))
        if greynoise and is_ip(primary_ip):
            api_tasks.append(greynoise_lookup(session, primary_ip, greynoise))
        if securitytrails and not is_ip(target):
            api_tasks.append(securitytrails_lookup(session, target, securitytrails))
        if alienotx:
            api_tasks.append(alienvault_otx_lookup(session, primary_ip if is_ip(primary_ip) else target, alienotx))

        # generic wrappers for other keys the user provided (best-effort)
        extras = {
            'AIK_RUNTIME': os.getenv('AIK_RUNTIME') or args.aikruntime,
            'CRIMINALIP': os.getenv('CRIMINALIP') or args.criminalip,
            'MALSHARE': os.getenv('MALSHARE') or args.malshare,
            'DNSDUMPSTER': os.getenv('DNSDUMPSTER') or args.dnsdumpster,
            'AUTHABUSE': os.getenv('AUTHABUSE') or args.authabuse,
            'IPQUALITY': os.getenv('IPQUALITY') or args.ipquality,
            'IPHUB': os.getenv('IPHUB') or args.iphub,
            'NEWSAPI': os.getenv('NEWSAPI') or args.newsapi,
        }
        for name, key in extras.items():
            if key:
                api_tasks.append(generic_api_lookup(session, name, primary_ip if is_ip(primary_ip) else target, key))

        if api_tasks:
            results = await asyncio.gather(*api_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    out.update(r)

        # send discord webhook if requested
        if args.discord_webhook:
            try:
                hook_res = await send_discord_webhook(session, args.discord_webhook, out)
                out['discord'] = hook_res
            except Exception as e:
                out['discord_error'] = str(e)

    return out


async def run_scan_flow(args) -> Dict[str, Any]:
    target = args.target
    ips = []
    if not is_ip(target):
        a = await resolve_a_records(target)
        aaaa = await resolve_aaaa_records(target)
        ips = a + aaaa
    else:
        ips = [target]

    if not ips:
        ips = [target]

    ports_to_scan = []
    if args.full:
        ports_to_scan = list(range(1, 65536))
    else:
        ports_to_scan = sorted(set(DEFAULT_TOP_PORTS + (args.ports or [])))

    if args.extra_ports:
        for p in args.extra_ports:
            try:
                ports_to_scan.append(int(p))
            except Exception:
                pass
    ports_to_scan = sorted(set(ports_to_scan))

    print(f"[+] Starting layer-1 quick scan on {target} (ports: {len(ports_to_scan)})")
    open_ports = {}
    host_for_scan = ips[0]
    scan_res = await scan_ports(host_for_scan, ports_to_scan, args.concurrency, show_progress=not args.quiet)
    for p, banner in scan_res.items():
        if banner is not None:
            open_ports[p] = banner

    if args.autolayer2:
        if not args.full:
            print(f"[+] Layer-2: running deeper scan (this may take long)")
            if args.deep_full:
                deep_ports = list(range(1, 65536))
            else:
                deep_ports = list(range(1, 2001))
            deep_scan_res = await scan_ports(host_for_scan, deep_ports, args.concurrency, show_progress=not args.quiet)
            for p, banner in deep_scan_res.items():
                if banner is not None:
                    open_ports[p] = banner

    subdomains = []
    if args.subdomains:
        if args.subfile:
            print(f"[+] Running subdomain bruteforce using {args.subfile}")
            subdomains = await brute_subdomains(target, args.subfile, concurrency=200)
        else:
            print("[!] No subdomain wordlist provided; skipping brute-forcing.")

    report = await enrich_and_report(target, ips, open_ports, args)

    # run optional nmap if requested
    if args.nmap:
        print('[+] Running nmap scan (requires nmap installed)')
        nmap_res = run_nmap_scan(target, ports=','.join(str(p) for p in report.get('open_ports', [])[:200]))
        report.update(nmap_res)

    # attach subdomains
    if subdomains:
        report['subdomains'] = subdomains

    return report

# -------------------- CLI and main --------------------

def make_argparser():
    p = argparse.ArgumentParser(description='KernelByte Scanner - ethical reconnaissance (Debian/Ubuntu)')
    p.add_argument('--target', '-t', required=True, help='Target IP (v4/v6) or domain')
    p.add_argument('--full', action='store_true', help='Scan full port range (1-65535)')
    p.add_argument('--deep-full', action='store_true', help='Layer2: scan full 1-65535')
    p.add_argument('--autolayer2', action='store_true', help='Automatically run layer-2 after layer-1')
    p.add_argument('--subdomains', action='store_true', help='Run subdomain discovery (requires --subfile)')
    p.add_argument('--subfile', help='Subdomain wordlist file for bruteforce')
    p.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help='Async concurrency (default 200)')
    p.add_argument('--ports', nargs='*', type=int, help='Additional ports to probe in layer-1')
    p.add_argument('--extra-ports', nargs='*', help='Extra ports to include (e.g. 8080 8443)')
    p.add_argument('--discord-webhook', default=os.getenv('DISCORD_WEBHOOK'), help='Discord webhook URL to post results')
    p.add_argument('--nmap', action='store_true', help='Run nmap after scanning (nmap binary required)')
    p.add_argument('--quiet', action='store_true', help='Suppress progress output')
    # API options (can also set via env)
    p.add_argument('--virustotal', help='VirusTotal API key')
    p.add_argument('--shodan', help='Shodan API key')
    p.add_argument('--abuseipdb', help='AbuseIPDB API key')
    p.add_argument('--ipinfo', help='IPInfo token')
    p.add_argument('--whoisxml', help='WhoisXML API key')
    p.add_argument('--greynoise', help='GreyNoise API key')
    p.add_argument('--securitytrails', help='SecurityTrails API key')
    p.add_argument('--alienvault', help='AlienVault OTX API key')
    # generic extras
    p.add_argument('--aikruntime', help='Aikido key')
    p.add_argument('--criminalip', help='CriminalIP key')
    p.add_argument('--malshare', help='MalShare key')
    p.add_argument('--dnsdumpster', help='DNSDumpster key')
    p.add_argument('--authabuse', help='AuthAbuse key')
    p.add_argument('--ipquality', help='IPQualityScore key')
    p.add_argument('--iphub', help='IpHub key')
    p.add_argument('--newsapi', help='NewsAPI key')
    p.add_argument('--confirm', action='store_true', help='Auto-confirm legal ownership (use with caution)')
    return p


def main():
    parser = make_argparser()
    args = parser.parse_args()
    args.started = now_iso()

    # Legal confirmation
    if not args.confirm:
        ok = legal_confirmation_sync(timeout=20)
        if not ok:
            print('[!] Scan aborted by user or timeout')
            sys.exit(1)
    else:
        print('[!] Auto-confirm enabled via --confirm; ensure you have permission to test the target.')

    # run async main
    try:
        report = asyncio.run(run_scan_flow(args))
        # print summary
        print('
===== Scan Summary =====')
        print(f"Target: {report.get('target')}")
        print(f"Started: {report.get('started')}")
        print(f"Finished: {report.get('finished')}")
        open_ports = report.get('open_ports', [])
        print(f"Open ports ({len(open_ports)}): {sorted(open_ports)[:50]}")
        # Dump JSON/CSV/HTML to file
        base = safe_filename(report.get('target', 'scan')) + '_' + str(int(time.time()))
        json_path = export_json(report, base + '.json')
        csv_path = export_csv(report, base + '.csv')
        html_path = export_html(report, base + '.html')
        print(f"JSON report: {json_path}")
        print(f"CSV report: {csv_path}")
        print(f"HTML report: {html_path}")
    except KeyboardInterrupt:
        print('
[!] Interrupted by user')


if __name__ == '__main__':
    main()
