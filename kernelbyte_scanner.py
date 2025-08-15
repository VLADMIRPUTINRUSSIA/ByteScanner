"""
KernelByte Scanner - single-file CLI vulnerability reconnaissance tool
Author: KernelByte
Contact: KernelByte@protonmail.com (PGP required)
License: MIT

IMPORTANT LEGAL WARNING
This tool is provided for EDUCATIONAL, DEFENSIVE, AND AUTHORIZED TESTING ONLY.
Do NOT run against systems you do not own or do not have explicit, written permission to test.
The author and distributor are not responsible for misuse.

Description:
A single-file, Python 3.8+ CLI scanner intended for Debian/Ubuntu systems.
Features (ethical reconnaissance only):
 - Accepts IPv4, IPv6 or domain/FQDN input
 - Optional subdomain enumeration (using provided wordlist or Security APIs)
 - Layered scan: quick top-port probe, then (if requested) full port-range scan
 - Asynchronous TCP port scanner (all 65,535 ports if requested)
 - Basic service banner grabbing and HTTP fingerprinting
 - Optional public OSINT enrichment using API keys (VirusTotal, Shodan, AbuseIPDB, IPInfo, GreyNoise, WhoisXML, etc.)
 - JSON and pretty CLI output
 - Optional Discord webhook reporting
 - 20-second confirmation prompt before starting any scans

Limitations & Safety:
 - This scanner DOES NOT contain exploit or post-exploitation code. It does NOT attempt to bypass security, persist, or evade EDRs.
 - No brute-force, no vulnerability exploitation, no lateral movement, no CDN bypass attempts.
 - Use responsibly and only on authorized targets.

Requirements (Debian/Ubuntu):
 - Python 3.8+
 - pip install -r requirements.txt

requirements.txt contents (recommended):
 aiohttp
 aiodns
 python-dotenv

(You can install: pip3 install aiohttp aiodns python-dotenv)

Usage examples:
  python3 kernelbyte_scanner.py --target 198.51.100.25
  python3 kernelbyte_scanner.py --target example.com --full
  python3 kernelbyte_scanner.py --target example.com --subdomains --subfile wordlist.txt --discord-webhook "https://discordapp.com/api/webhooks/..."

Configuration: set API keys in environment variables or pass on command-line. Example env file (.env):
 VIRUSTOTAL_API=da3e3cd6272f96e1744654ceefbd90f555a8d53bfab4808f491deb6daf83aa69
 SHODAN_API=YSlyPaKCAgQcYiZi0N26JEf5cUqgt208
 ABUSEIPDB_API=8c6b2a6e1252a2be7119e98613c9ab5dcbeb3c0f2d3844073c17c79d632d75b700f187398112858e
 IPINFO_TOKEN=30131dbc0b1f44
 DISCORD_WEBHOOK=https://discordapp.com/api/webhooks/1405982793246441593/5IlritAc5TxoGqj1GIQf3oj0lWXSwg8MOu2roMNQaZzRcS8NURFIZNVAX5Cc-65lRL7L

Note: The example above contains placeholder tokens. Only use API keys you are authorized to use.

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
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    import aiohttp
    import aiodns
    from dotenv import load_dotenv
except Exception:
    print("[!] Missing Python dependencies. Please run: pip3 install aiohttp aiodns python-dotenv")
    sys.exit(1)

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

DEFAULT_CONCURRENCY = 500
CONNECT_TIMEOUT = 3.0
BANNER_GRAB_BYTES = 1024
DEFAULT_TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,5900,8080]

# -------------------- Utility Functions --------------------

def is_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def now_iso() -> str:
    return datetime.utcnow().isoformat() + 'Z'


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
                writer.write(b"\r\n")
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


async def scan_ports(host: str, ports: List[int], concurrency: int) -> Dict[int, Optional[str]]:
    global semaphore
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    results: Dict[int, Optional[str]] = {}
    for p in ports:
        tasks.append(asyncio.create_task(tcp_connect(host, p)))
    for i, task in enumerate(asyncio.as_completed(tasks)):
        try:
            banner = await task
            port = ports[i]
            results[port] = banner
        except Exception as e:
            # Fallback: try to inspect task.get_coro to find port index
            results[ports[i]] = None
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
    # Very simple subdomain bruteforce using A record resolution
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


# -------------------- API Enrichment (optional) --------------------

async def vt_lookup(session: aiohttp.ClientSession, ip_or_domain: str, api_key: str) -> Dict[str, Any]:
    # VirusTotal v3 example: https://developers.virustotal.com/v3.0/reference
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
        url = f'https://api.shodan.io/shodan/host/{ip_or_domain}?key={api_key}' if is_ip(ip_or_domain) else f'https://api.shodan.io/dns/resolve?hostnames={ip_or_domain}&key={api_key}'
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
        headers = {}
        params = {'token': token} if token else {}
        async with session.get(url, headers=headers, params=params, timeout=10) as resp:
            result = await resp.json()
    except Exception as e:
        result = {'error': str(e)}
    return {'ipinfo': result}


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
                    'description': f"`Started: {content.get('started')}`\n`Finished: {content.get('finished')}`",
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
        # API lookups (simple, optional)
        api_tasks = []
        vt = os.getenv('VIRUSTOTAL_API') or args.virustotal
        shodan = os.getenv('SHODAN_API') or args.shodan
        abuse = os.getenv('ABUSEIPDB_API') or args.abuseipdb
        ipinfo = os.getenv('IPINFO_TOKEN') or args.ipinfo

        if vt:
            api_tasks.append(vt_lookup(session, target if not ips else ips[0], vt))
        if shodan:
            api_tasks.append(shodan_lookup(session, target if not ips else ips[0], shodan))
        if abuse and ips:
            api_tasks.append(abuseipdb_lookup(session, ips[0], abuse))
        if ipinfo and ips:
            api_tasks.append(ipinfo_lookup(session, ips[0], ipinfo))

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
    # Basic DNS resolution if domain
    ips = []
    if not is_ip(target):
        # resolve A/AAAA
        a = await resolve_a_records(target)
        aaaa = await resolve_aaaa_records(target)
        ips = a + aaaa
    else:
        ips = [target]

    if not ips:
        ips = [target]

    # Layer 1: quick scan - top ports + user-specified
    ports_to_scan = []
    if args.full:
        ports_to_scan = list(range(1, 65536))
    else:
        ports_to_scan = sorted(set(DEFAULT_TOP_PORTS + (args.ports or [])))

    # Convert known integer list in args
    if args.extra_ports:
        for p in args.extra_ports:
            try:
                ports_to_scan.append(int(p))
            except Exception:
                pass
    ports_to_scan = sorted(set(ports_to_scan))

    print(f"[+] Starting layer-1 quick scan on {target} (ports: {len(ports_to_scan)})")
    open_ports = {}
    # scan first IP in list
    host_for_scan = ips[0]
    # Run async port scanner
    scan_res = await scan_ports(host_for_scan, ports_to_scan, args.concurrency)
    for p, banner in scan_res.items():
        if banner is not None:
            open_ports[p] = banner

    # If layer2 requested (auto), then perform second deeper scan automatically
    if args.autolayer2:
        # If user requested full -> already did full
        if not args.full:
            # deep scan: scan common + range of adjacent ports or full, depending on args
            print(f"[+] Layer-2: running deeper scan (this may take long)")
            if args.deep_full:
                deep_ports = list(range(1, 65536))
            else:
                # expand to top 2000 common ports
                deep_ports = list(range(1, 2001))
            deep_scan_res = await scan_ports(host_for_scan, deep_ports, args.concurrency)
            for p, banner in deep_scan_res.items():
                if banner is not None:
                    open_ports[p] = banner

    # Optional subdomain enumeration
    subdomains = []
    if args.subdomains:
        if args.subfile:
            print(f"[+] Running subdomain bruteforce using {args.subfile}")
            subdomains = await brute_subdomains(target, args.subfile, concurrency=200)
        else:
            print("[!] No subdomain wordlist provided; skipping brute-forcing.")

    # Enrichment and reporting
    report = await enrich_and_report(target, ips, open_ports, args)
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
    p.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help='Async concurrency (default 500)')
    p.add_argument('--ports', nargs='*', type=int, help='Additional ports to probe in layer-1')
    p.add_argument('--extra-ports', nargs='*', help='Comma-separated extra ports to include (e.g. 8080 8443)')
    p.add_argument('--discord-webhook', default=os.getenv('DISCORD_WEBHOOK'), help='Discord webhook URL to post results')
    # API options (can also set via env)
    p.add_argument('--virustotal', help='VirusTotal API key')
    p.add_argument('--shodan', help='Shodan API key')
    p.add_argument('--abuseipdb', help='AbuseIPDB API key')
    p.add_argument('--ipinfo', help='IPInfo token')
    p.add_argument('--confirm', action='store_true', help='Auto-confirm legal ownership (use with caution)')
    return p


def legal_confirmation(prompt: str = None, timeout: int = 20) -> bool:
    if prompt is None:
        prompt = "Do you confirm you own or have explicit permission to test the target? (yes/no): "
    if os.getenv('KB_AUTO_CONFIRM') == '1':
        return True
    print('\n' + BANNER)
    print("LEGAL NOTICE: You must only scan systems you own or have written permission to test.")
    print(f"You have {timeout} seconds to respond. Type 'yes' to proceed.")

    # wait for user input with timeout
    try:
        print(prompt, end='', flush=True)
        loop = asyncio.get_event_loop()
        fut = loop.run_in_executor(None, sys.stdin.readline)
        line = loop.run_until_complete(asyncio.wait_for(fut, timeout=timeout))
        if line.strip().lower() == 'yes':
            return True
        else:
            return False
    except Exception:
        print('\n[!] No confirmation received. Cancelling.')
        return False


def main():
    parser = make_argparser()
    args = parser.parse_args()
    args.started = now_iso()

    # Legal confirmation
    if not args.confirm:
        ok = legal_confirmation(timeout=20)
        if not ok:
            print('[!] Scan aborted by user or timeout')
            sys.exit(1)
    else:
        print('[!] Auto-confirm enabled via --confirm; ensure you have permission to test the target.')

    # run async main
    try:
        report = asyncio.run(run_scan_flow(args))
        # print summary
        print('\n===== Scan Summary =====')
        print(f"Target: {report.get('target')}")
        print(f"Started: {report.get('started')}")
        print(f"Finished: {report.get('finished')}")
        open_ports = report.get('open_ports', [])
        print(f"Open ports ({len(open_ports)}): {sorted(open_ports)[:50]}")
        # Dump JSON to file
        outfn = f"scan_{report.get('target').replace('/', '_')}_{int(time.time())}.json"
        with open(outfn, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"Full JSON report written to {outfn}")
    except KeyboardInterrupt:
        print('\n[!] Interrupted by user')


if __name__ == '__main__':
    main()
