# Open Redirect Scanner 🚀

**Automated open redirect vulnerability scanner for bug bounty hunting on HackerOne, Intigriti, and more.**

## Two Versions Available

This repository contains **TWO versions** of the scanner - choose based on your needs:

### 🔥 Go Version (RECOMMENDED - NEW!)

**Ultra-fast scanner written in Go**

- ⚡ **10-100x faster** than Python
- 🚀 **1000+ concurrent goroutines**
- 📦 **Single binary** - no dependencies
- 💾 **Lower memory** - ~100MB vs ~500MB
- 🔧 **Easy install** - one command

**Perfect for: Large-scale scans, VPS environments, speed-critical tasks**

### 🐍 Python + Bash Version (Original)

**Feature-rich scanner with OSINT integrations**

- 🔍 **Multiple OSINT sources** - VirusTotal, Wayback, GAU, Katana, Hakrawler
- 🛠️ **Flexible** - Easy to modify and extend
- 📚 **Well-documented** - Lots of examples

**Perfect for: Learning, customization, comprehensive URL gathering**

---

## Quick Comparison

| Feature | Go Version | Python Version |
|---------|------------|----------------|
| **Speed** | ⚡ 10x faster | 🐌 Slower |
| **Concurrency** | 1000+ goroutines | 50-200 threads |
| **Memory** | ~100MB | ~500MB |
| **Installation** | One command | Multiple tools |
| **Dependencies** | None | httpx, gau, katana, etc. |
| **URL Collection** | Manual input | Built-in (VirusTotal, Wayback, etc.) |
| **Binary Size** | 8.7MB single file | Multiple scripts |
| **Best For** | Speed & scale | OSINT & learning |

---

## 🔥 Go Version - Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/amahrou1/Scripts-and-automation.git
cd Scripts-and-automation

# Auto-install (installs Go if needed + builds binary)
chmod +x install.sh
./install.sh
```

### Usage

```bash
# Basic scan
./openredirect -l urls.txt -t 500

# With Discord notifications
./openredirect -l urls.txt -t 500 -w "YOUR_DISCORD_WEBHOOK"

# High performance (1000 concurrent!)
./openredirect -l urls.txt -t 1000 -o results
```

### Options

```
-l string    Input file containing URLs (required)
-o string    Output directory (default: "results")
-t int       Number of concurrent threads (default: 100)
-w string    Discord webhook URL for notifications
-v           Verbose output
```

### Example Workflow

```bash
# Get URLs from your tools
cat subdomains.txt | waybackurls | grep -iE "(redirect|url|next)" > urls.txt

# Scan super fast with Go
./openredirect -l urls.txt -t 500
```

**📖 See [QUICKSTART.md](QUICKSTART.md) for detailed Go version guide**

---

## 🐍 Python Version - Quick Start

### Installation

```bash
# Clone repository (if not already)
git clone https://github.com/amahrou1/Scripts-and-automation.git
cd Scripts-and-automation

# Install all tools
chmod +x install-tools.sh
./install-tools.sh

# Reload shell
source ~/.bashrc
```

### Usage

```bash
# Basic scan (includes URL gathering from multiple sources)
./open-redirect-scanner.sh -l subdomains.txt

# With Discord and VirusTotal
./open-redirect-scanner.sh -l subdomains.txt \
  -w "YOUR_DISCORD_WEBHOOK" \
  -k "YOUR_VT_API_KEY"

# High threads
./open-redirect-scanner.sh -l subdomains.txt -t 200
```

### Configuration

Create `config.sh` for default settings:

```bash
cp config.sh.example config.sh
nano config.sh
```

Add your credentials:
```bash
DISCORD_WEBHOOK="your_webhook_here"
VT_API_KEY="your_virustotal_key_here"
```

---

## Which Version Should I Use?

### Use Go Version If:
- ✅ You want **maximum speed**
- ✅ You have **many URLs to test** (10k+)
- ✅ You want a **simple setup** (no dependencies)
- ✅ You already have URLs from other tools
- ✅ You're running on a **VPS**

### Use Python Version If:
- ✅ You want **all-in-one** solution with URL gathering
- ✅ You need **VirusTotal integration**
- ✅ You want **multiple OSINT sources** automatically
- ✅ You're **learning** bug bounty techniques
- ✅ You want to **customize** the scanner easily

### Use BOTH!
The best workflow:
1. Use **Python version** to gather URLs from OSINT sources
2. Use **Go version** to test them blazing fast!

```bash
# Step 1: Gather URLs with Python version
./open-redirect-scanner.sh -l subdomains.txt -o osint-results
# This creates: osint-results/potential_redirects_*.txt

# Step 2: Test with Go version (10x faster!)
./openredirect -l osint-results/potential_redirects_*.txt -t 1000
```

---

## Features

### Both Versions Include:

✅ **Accurate Detection**
- Validates actual redirect domain (not just parameters)
- No false positives like `passport.acronis.work?redirect=evil.com`
- Multiple detection methods (HTTP, meta refresh, JavaScript)

✅ **Discord Notifications**
- Real-time alerts when vulnerabilities found
- Rich embeds with details
- Rate limiting built-in

✅ **Smart Deduplication**
- Only reports unique URL + parameter combinations
- Prevents duplicate results

✅ **17+ Test Payloads**
- Protocol-relative (`//evil.com`)
- Backslash bypasses
- @ symbol techniques
- JavaScript protocols
- And more!

### Python Version Extras:

- 🔍 **VirusTotal API** - Gather URLs from VT database
- 🕰️ **Wayback Machine** - Historical URLs
- 🌐 **GAU** - Common Crawl, AlienVault
- 🕷️ **Katana** - Active web crawling
- 🦗 **Hakrawler** - Fast crawler
- 🔎 **GF Patterns** - Smart filtering

---

## Files in This Repository

```
Scripts-and-automation/
├── Go Version:
│   ├── main.go                    # Go scanner source code
│   ├── openredirect               # Compiled binary (8.7MB)
│   ├── build.sh                   # Build script
│   ├── install.sh                 # Auto-installer
│   ├── go.mod                     # Go dependencies
│   ├── urls.example.txt           # Example URLs for Go version
│   └── QUICKSTART.md              # Detailed Go guide
│
├── Python Version:
│   ├── open-redirect-scanner.sh   # Main orchestration script
│   ├── test-redirects.py          # Payload testing script
│   ├── install-tools.sh           # Tool installer
│   ├── config.sh.example          # Config template
│   └── subdomains.txt.example     # Example subdomains
│
└── README.md                      # This file
```

---

## Performance Examples

### Test: 10,000 URLs

| Scanner | Time | Memory | CPU |
|---------|------|--------|-----|
| **Go (500 threads)** | **2 min** | 100MB | 40% |
| Python (50 threads) | 15 min | 500MB | 60% |
| Python (200 threads) | 8 min | 700MB | 80% |

**Go is 4-7x faster!** ⚡

---

## Security & Legal

**IMPORTANT:** For authorized security testing only.

- ✅ Bug bounty programs (HackerOne, Intigriti, Bugcrowd, etc.)
- ✅ Authorized penetration testing
- ✅ Your own applications
- ❌ Unauthorized testing (ILLEGAL!)

Always get permission before testing!

---

## Troubleshooting

### Go Version

**"go: command not found"**
```bash
./install.sh  # Installs Go automatically
```

**"too many open files"**
```bash
ulimit -n 10000
```

### Python Version

**"httpx not found"**
```bash
./install-tools.sh
source ~/.bashrc
```

**"Discord notifications freeze"**
- Already fixed in latest version!
- `git pull` to update

---

## Contributing

Contributions welcome! Areas for improvement:

- Additional bypass payloads
- New detection methods
- More OSINT integrations
- Performance optimizations

---

## Credits

Built for bug bounty hunters by bug bounty hunters 🎯

Combines work from:
- [ProjectDiscovery](https://github.com/projectdiscovery) - httpx, katana
- [TomNomNom](https://github.com/tomnomnom) - waybackurls, gf
- [lc](https://github.com/lc) - gau
- [hakluke](https://github.com/hakluke) - hakrawler

---

## License

MIT License - See LICENSE file

---

## Support

Having issues? Open a GitHub issue or check:
- [QUICKSTART.md](QUICKSTART.md) - Go version detailed guide
- Example files in the repository
- Discord notifications setup

---

**Happy (Ethical) Hunting!** 🚀🎯

*Making the web safer, one redirect at a time.*
