<!--
  SecSub README – optimized for search engines & social previews
  Keywords: subdomain enumeration, subdomain finder, bug bounty recon, OSINT, security automation, SecOpsElite
-->

# 🚀 SecSub – The Supreme **Sub‑domain Hunter** & Live Host Probe

*High‑performance python tool for bug‑bounty recon, red‑teaming & attack‑surface mapping*

[![SecSub by SecOpsElite](https://img.shields.io/badge/SecOpsElite‑SecSub-%23007acc?style=for-the-badge\&logo=github)](https://github.com/SecOpsElite)
[![License](https://img.shields.io/github/license/SecOpsElite/secsub?style=flat-square)](LICENSE)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=flat-square) ![Last Commit](https://img.shields.io/github/last-commit/SecOpsElite/secsub?style=flat-square) ![Issues](https://img.shields.io/github/issues/SecOpsElite/secsub?style=flat-square)

<div align="center">
  <img src="docs/demo.gif" alt="SecSub demo animation" width="720"><br>
  <sub>*GIF: Discovering & probing 5 000+ sub‑domains for example.com in under 90 seconds*<sub>
</div>

> **SecSub** is an open‑source, Python‑powered **sub‑domain enumeration** & **live host checker** that combines **12+ passive OSINT feeds** with a lightning‑fast **DNS + HTTP probe engine**. Perfect for **bug bounty hunters**, **pentesters**, and **blue‑teams** who want **full attack‑surface visibility** without paid APIs.

---

## 📑 Table of Contents

1. [Features](#-features)
2. [Installation](#-installation)
3. [Quick Start](#-quick-start)
4. [CLI Reference](#-cli-reference)
5. [Sample Output](#-sample-output)
6. [Roadmap](#-roadmap)
7. [Contributing](#-contributing)
8. [License](#-license)

---

## ✨ Features

| Category                      | Description                                                                                                                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **📡 Passive OSINT**          | Aggregates 12+ data sources including Certificate Transparency (crt.sh), Wayback Machine, ThreatCrowd & BufferOver DNS for maximum coverage. |
| **🔍 Brute‑force Engine**     | Intelligent wordlist + prefix/suffix permutations resolved over DNS‑over‑HTTPS (Cloudflare 1.1.1.1 & Google 8.8.8.8).                        |
| **🌐 IPv4 & IPv6**            | Detects hosts with `A` **and** `AAAA` records – no blind spots on dual‑stack estates.                                                        |
| **⚡ Async HTTP/S Probe**      | Mass‑checks thousands of hosts in parallel (`aiohttp`) and filters out dead targets instantly.                                               |
| **🖥️ Rich CLI UX**           | Colorized banners & live progress bars courtesy of the `rich` library – see exactly what’s happening in real‑time.                           |
| **📊 Multi‑format Reports**   | Generates `subdomains.txt`, `live_subdomains.txt`, machine‑readable `report.json`, and a slick dark‑mode `index.html`.                       |
| **🔧 Zero External Binaries** | Pure‑Python – runs on Windows, macOS & Linux with only `pip install -r requirements.txt`.                                                    |

---

## 💾 Installation

```bash
# Clone the repo
$ git clone https://github.com/SecOpsElite/secsub.git && cd secsub

# Install dependencies (rich, aiohttp, dnspython)
$ python -m pip install -r requirements.txt
```

> **Tip:** Use a virtualenv or Conda env for tidy dependency management.

---

## ⚡ Quick Start

```bash
# Basic enumeration + liveness check
$ python secsub.py -d example.com

# Advanced mode: custom wordlist, output dir & more threads
$ python secsub.py -d example.com \
                  -w wordlists/top2k.txt \
                  -o recon‑results/ \
                  -t 800 --dns-threads 1000 --timeout 5
```

A dark‑mode HTML report will appear in `recon-results/example.com/index.html` – perfect for sharing with teammates or embedding in Jira tickets.

---

## 🛠️ CLI Reference

```text
-d, --domain       Apex domain to scan (required)
-w, --wordlist     Text file with sub‑domain prefixes (optional)
-o, --output       Output directory (default: ./reports)
-t, --threads      HTTP probe concurrency (default: 400)
--dns-threads      DNS brute concurrency (default: 500)
--timeout          HTTP timeout seconds (default: 8)
```

---

## 📂 Sample Output

```
reports/
└── example.com/
    ├── subdomains.txt        # 4 922 unique hosts
    ├── live_subdomains.txt   # 1 764 live hosts
    ├── report.json           # JSON summary/automation‑friendly
    └── index.html            # Dark‑mode interactive report
```

> **SEO pro‑tip:** Host the `example.com` directory on GitHub Pages to share results publicly or embed in Write‑ups.

---

## 🗺️ Roadmap

* [ ] Wildcard DNS detection & exclusion
* [ ] Screenshots of live hosts via headless Chrome
* [ ] CSV & XLSX export
* [ ] Nmap port‑sweep integration (opt‑in)

---

## 🤝 Contributing

Pull requests, bug reports & feature requests are **welcome**! Fork the repo → create a branch → submit a PR.
If SecSub helped you find a bug, **star** ⭐ the project and share the love on Twitter/LinkedIn.

---

## 📝 License

MIT © 2025 [SecOpsElite](https://github.com/SecOpsElite)
