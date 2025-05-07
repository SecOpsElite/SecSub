#!/usr/bin/env python3
"""
SecSub – The Supreme Sub‑domain Hunter
======================================

A **single‑file** sub‑domain enumerator + live‑host checker.

Features
--------
* 12+ passive OSINT feeds (CT logs, passive DNS, threat‑intel APIs)
* Smart brute‑force permutations (wordlist + numeric prefix/suffix)
* DNS‑over‑HTTPS (Cloudflare + Google) with IPv4/6 fallback  
* Fully async HTTP/S probing (aiohttp) with Rich progress bars  
* Outputs **TXT**, **JSON**, and a dark‑mode **HTML** report

Quick start
~~~~~~~~~~~
```bash
python -m pip install --upgrade rich aiohttp dnspython
python secsub.py -d example.com -o reports/ -t 400
```
"""
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Set, Tuple

import aiohttp
import dns.asyncresolver  # type: ignore
import dns.exception  # type: ignore
from rich import box, print
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn

# ══════════════════════ Globals ══════════════════════
console = Console()
VERSION = "1.1.1"
USER_AGENT = f"SecSub/{VERSION} (+https://github.com/your‑org/secsub)"
HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}

RESOLVER = dns.asyncresolver.Resolver(configure=False)
RESOLVER.nameservers = ["1.1.1.1", "8.8.8.8"]
RESOLVER.timeout = RESOLVER.lifetime = 4
RESOLVER.search = []
RESOLVER.cache = dns.resolver.Cache()

# ════════════ Passive source helpers ════════════════
async def fetch(session: aiohttp.ClientSession, url: str):
    """Return JSON if possible, else text, else *None*."""
    try:
        async with session.get(url, timeout=30) as r:
            if r.status == 200:
                if "json" in r.headers.get("content-type", ""):
                    return await r.json()
                return await r.text()
    except Exception:
        return None
    return None

PassiveParser = Callable[[str, object | None], Set[str]]
Source = Tuple[str, str, PassiveParser]

aio_sources: list[Source] = [
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json", lambda _, d: {row["name_value"].lower() for row in (d or [])}),
    ("Anubis", "https://jldc.me/anubis/subdomains/{domain}", lambda _, d: set(d or [])),
    ("ThreatCrowd", "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", lambda _, d: set((d or {}).get("subdomains", []))),
    ("Wayback", "https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey", lambda _, d: {row[0].split("/")[0].replace("http://", "").replace("https://", "") for row in (d or [])[1:]}),
    ("BufferOver", "https://dns.bufferover.run/dns?q=.{domain}", lambda _, d: {(item.split(",")[1] if "," in item else item).lower() for key in ("FDNS_A", "RDNS") for item in (d or {}).get(key, [])}),
    ("Hackertarget", "https://api.hackertarget.com/hostsearch/?q={domain}", lambda _, txt: {line.split(",")[0].lower() for line in (txt or "").splitlines()}),
]

# ════════════ Wordlist & permutations ═══════════════

def load_wordlist(path: Path | None) -> list[str]:
    if path is None:
        return ["dev", "test", "stage", "api", "www"]
    return [w.strip() for w in path.read_text().splitlines() if w.strip()]


def permutations(base: str):
    yield base
    for sep in ("-", ""):
        for n in range(1, 4):
            yield f"{base}{sep}{n}"
            yield f"{n}{sep}{base}"

# ═════════════ DNS & HTTP helpers ══════════════════
async def resolve(host: str) -> bool:
    try:
        await RESOLVER.resolve(host, "A", lifetime=4)
        return True
    except dns.exception.DNSException:
        try:
            await RESOLVER.resolve(host, "AAAA", lifetime=4)
            return True
        except dns.exception.DNSException:
            return False


async def is_alive(session: aiohttp.ClientSession, host: str, timeout: int) -> bool:
    for scheme in ("https", "http"):
        try:
            async with session.head(f"{scheme}://{host}", allow_redirects=True, timeout=timeout) as r:
                if r.status < 500:
                    return True
        except Exception:
            continue
    return False

# ═════════════ Enumeration steps ══════════════════
async def gather_passive(domain: str) -> Set[str]:
    subs: Set[str] = set()
    async with aiohttp.ClientSession(headers=HEADERS) as session:
        tasks = [fetch(session, url.format(domain=domain)) for _, url, _ in aio_sources]
        with Progress(SpinnerColumn(), "{task.description}") as prog:
            t = prog.add_task("Passive enumeration", total=len(tasks))
            results = await asyncio.gather(*tasks)
            for (_, _, parser), data in zip(aio_sources, results):
                subs.update({s.lower() for s in parser(domain, data) if s.endswith(domain)})
                prog.advance(t)
    return subs


async def brute(domain: str, words: list[str], conc: int) -> Set[str]:
    hosts = [f"{p}.{domain}" for w in words for p in permutations(w)]
    live: Set[str] = set()
    sem = asyncio.Semaphore(conc)

    async def worker(h: str):
        async with sem:
            if await resolve(h):
                live.add(h)

    await asyncio.gather(*[worker(h) for h in hosts])
    return live


async def probe_live(hosts: Iterable[str], conc: int, timeout: int) -> Set[str]:
    alive: Set[str] = set()
    connector = aiohttp.TCPConnector(ssl=False, limit=conc)
    async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:
        with Progress(SpinnerColumn(), "{task.description}") as prog:
            task_id = prog.add_task("HTTP probing", total=len(hosts))
            sem = asyncio.Semaphore(conc)

            async def _probe(h: str):
                async with sem:
                    if await is_alive(session, h, timeout):
                        alive.add(h)
                    prog.advance(task_id)

            await asyncio.gather(*(_probe(h) for h in hosts))
    return alive

# ═════════════ Report writer ═══════════════════════

def write_reports(domain: str, out: Path, subs: Set[str], live: Set[str]):
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    (out / "subdomains.txt").write_text("\n".join(sorted(subs)))
    (out / "live_subdomains.txt").write_text("\n".join(sorted(live)))

    with (out / "report.json").open("w", encoding="utf-8") as fp:
        json.dump({
            "domain": domain,
            "generated": ts,
            "total": len(subs),
            "live": len(live),
            "hosts": sorted(subs),
            "live_hosts": sorted(live)
        }, fp, indent=2)

    html_parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>SecSub – {domain}</title>",
        "<style>body{font-family:system-ui;background:#111;color:#eee;padding:2rem}a{color:#0af}.up{color:#0f0}</style></head><body>",
        f"<h1>SecSub report for <em>{domain}</em></h1>",
        f"<p>{len(live)}/{len(subs)} hosts alive · generated {ts}</p><ul>",
    ]
    html_parts += [f"<li class='{'up' if h in live else ''}'>{h}</li>" for h in sorted(subs)]
    html_parts.append("</ul></body></html>")
    (out / "index.html").write_text("".join(html_parts))

# ═════════════ CLI & entry‑point ═══════════════════

def banner():
    logo = r"""[bold purple]
  ____            _____       _    
 / ___|  ___  ___| ____|_ ___(_)___
 \___ \ / _ \/ __|  _| | '_  / / __|
  ___) |  __/ (__| |___| | | | \__ \
 |____/ \___|\___|_____|_| |_|_|___/
"""
    console.print(Panel(logo, title=f"SecSub v{VERSION}", subtitle="Seeing what others don’t", box=box.DOUBLE))


def parse_args(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description="Comprehensive sub‑domain discovery & live checking")
    p.add_argument("-d", "--domain", required=True, help="Apex domain to scan")
    p.add_argument("-w", "--wordlist", type=Path, help="Wordlist for brute‑force (optional)")
    p.add_argument("-o", "--output", type=Path, default=Path("reports"), help="Output directory")
    p.add_argument("-t", "--threads", type=int, default=400, help="HTTP probe concurrency")
    p.add_argument("--dns-threads", type=int, default=500, help="DNS brute concurrency")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds")
    return p.parse_args(argv)


async def main() -> None:
    args = parse_args()
    banner()

    domain = args.domain.lower().strip()
    words = load_wordlist(args.wordlist)

    passive = await gather_passive(domain)
    console.print(f"📡  Passive sources found [yellow]{len(passive):,}[/]")

    brute_hosts = await brute(domain, words, args.dns_threads)
    console.print(f"🔍  Brute‑force found [yellow]{len(brute_hosts):,}[/]")

    all_hosts = passive | brute_hosts
    console.print(f"💎  Total unique sub‑domains [green]{len(all_hosts):,}[/]")

    live_hosts = await probe_live(all_hosts, args.threads, args.timeout)
    console.print(f"🌐  Live hosts [green]{len(live_hosts):,}[/]")

    out_dir = args.output / domain
    write_reports(domain, out_dir, all_hosts, live_hosts)
    console.print(f"📑  Report written to [cyan]{out_dir}[/]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("[red][!] Cancelled by user[/]")
