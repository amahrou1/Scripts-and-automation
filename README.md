# Open Redirect Scanner

A comprehensive, automated tool for discovering open redirect vulnerabilities during bug bounty hunting. This scanner combines multiple OSINT sources and security tools to efficiently find and test potential open redirect bugs.

## Features

- **Multi-source URL gathering**: Collects URLs from Wayback Machine, Common Crawl, GAU, and web crawling
- **Smart filtering**: Uses GF patterns and custom regex to identify potential redirect parameters
- **Automated testing**: Tests URLs with 40+ different open redirect payloads
- **Fast & Scalable**: Multi-threaded processing with configurable thread count
- **Comprehensive detection**: Detects redirects via HTTP headers, meta refresh, and JavaScript
- **Detailed reporting**: Generates organized reports with all findings

## Tools Used

This scanner orchestrates multiple industry-standard tools:

- **httpx**: Fast HTTP toolkit for probing and validation
- **waybackurls**: Fetches URLs from the Wayback Machine
- **gau**: GetAllURLs - fetches URLs from multiple sources (Wayback, Common Crawl, etc.)
- **katana**: Web crawler by ProjectDiscovery
- **hakrawler**: Fast web crawler
- **gf**: Pattern-based grep for filtering URLs
- **Python requests**: For testing open redirect payloads

## Installation

### Quick Install

```bash
chmod +x install-tools.sh
./install-tools.sh
```

After installation, reload your shell:
```bash
source ~/.bashrc
```

### Manual Installation

If you prefer to install tools manually:

```bash
# Install Go
sudo apt update
sudo apt install -y golang-go

# Set up Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/gf@latest

# Install Python dependencies
pip3 install requests urllib3

# Install GF patterns
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-patterns
cp ~/.gf-patterns/*.json ~/.gf/
```

## Usage

### Basic Usage

```bash
chmod +x open-redirect-scanner.sh
./open-redirect-scanner.sh -l subdomains.txt
```

### Advanced Options

```bash
./open-redirect-scanner.sh -l subdomains.txt -o results -t 100 -v
```

### Parameters

- `-l, --list`: Input file containing subdomains (required)
- `-o, --output`: Output directory (default: open-redirect-results)
- `-t, --threads`: Number of threads (default: 50)
- `-v, --verbose`: Verbose output
- `-h, --help`: Show help message

## Input Format

Create a file named `subdomains.txt` with your target subdomains:

```
https://test.example.com
https://api.example.com
https://app.example.com
https://admin.example.com
```

## Output

The scanner creates a timestamped results directory with:

- `live_hosts_*.txt`: Validated live subdomains
- `urls_collected_*.txt`: All URLs gathered from various sources
- `potential_redirects_*.txt`: Filtered URLs with redirect parameters
- `valid_urls_*.txt`: Live URLs that responded
- `vulnerable_*.txt`: Confirmed open redirect vulnerabilities
- `scan_log_*.txt`: Detailed scan log

### Example Output

```
[VULNERABLE] https://example.com/redirect?url=https://evil.com
  └─ Parameter: url | Payload: https://evil.com | Reason: Redirect to external domain: https://evil.com
```

## How It Works

### Workflow

1. **Subdomain Validation**: Validates which subdomains are live using httpx
2. **URL Collection**: Gathers URLs from multiple sources:
   - Wayback Machine (waybackurls)
   - Common Crawl, AlienVault (gau)
   - Active crawling (katana, hakrawler)
3. **Filtering**: Identifies URLs with potential redirect parameters using gf patterns
4. **Validation**: Checks if filtered URLs are still live and responsive
5. **Testing**: Tests each URL with multiple open redirect payloads
6. **Reporting**: Generates detailed reports of findings

### Detection Methods

The scanner detects open redirects through:

- **HTTP 3xx redirects**: Monitors Location headers
- **Meta refresh tags**: Parses HTML meta refresh redirects
- **JavaScript redirects**: Detects window.location, location.href changes
- **Protocol-relative URLs**: Tests // and /// bypasses
- **Encoding bypasses**: Tests URL encoding variations
- **Special characters**: Tests @, \, whitespace bypasses

### Test Payloads

The scanner tests 40+ different payloads including:

- External domain redirects
- Protocol-relative redirects
- Special character bypasses
- URL encoding variations
- JavaScript protocol handlers
- Data URIs
- Unicode/IDN bypasses

## Examples

### Example 1: Basic Scan

```bash
# Create input file
echo "https://example.com" > subdomains.txt
echo "https://test.example.com" >> subdomains.txt

# Run scanner
./open-redirect-scanner.sh -l subdomains.txt

# Results will be in: open-redirect-results/
```

### Example 2: High-Performance Scan

```bash
# Scan with 200 threads for faster processing
./open-redirect-scanner.sh -l subdomains.txt -t 200 -o fast-scan
```

### Example 3: Verbose Scan

```bash
# Run with verbose output
./open-redirect-scanner.sh -l subdomains.txt -v
```

## Best Practices

### For Bug Bounty Hunters

1. **Always verify manually**: Automated scanners can have false positives
2. **Check scope**: Ensure targets are within the bug bounty program scope
3. **Test responsibly**: Use reasonable thread counts to avoid DoS
4. **Document findings**: Save all evidence for your reports
5. **Follow disclosure**: Report through proper channels only

### Optimization Tips

1. **Start with fewer threads**: Test with 50 threads, increase if needed
2. **Filter subdomains first**: Use tools like subfinder, amass first
3. **Run during off-peak hours**: Less likely to trigger rate limiting
4. **Use VPS**: Better bandwidth and stability than local machine
5. **Monitor resources**: Watch CPU and network usage

## Troubleshooting

### Tools not found

```bash
# Verify Go path is set
echo $GOPATH
echo $PATH

# Reload shell configuration
source ~/.bashrc

# Verify installation
httpx -version
```

### Permission denied

```bash
chmod +x open-redirect-scanner.sh
chmod +x test-redirects.py
chmod +x install-tools.sh
```

### No URLs collected

- Check if subdomains are correct and accessible
- Verify internet connection
- Some targets may have no historical data in archives
- Try increasing timeout values

### Rate limiting

- Reduce thread count with `-t` flag
- Add delays between requests
- Use VPN or proxy rotation (configure in tools)

## Security & Legal

**IMPORTANT**: This tool is for authorized security testing only.

- Only test applications you have permission to test
- Bug bounty programs on HackerOne, Intigriti, etc. provide authorization
- Unauthorized testing is illegal
- Follow responsible disclosure practices
- Do not use for malicious purposes

## Contributing

Contributions are welcome! Areas for improvement:

- Additional payload variations
- New URL collection sources
- Enhanced detection methods
- Performance optimizations
- Additional output formats

## Credits

This tool combines the excellent work of:

- [ProjectDiscovery](https://github.com/projectdiscovery) - httpx, katana
- [TomNomNom](https://github.com/tomnomnom) - waybackurls, gf
- [lc](https://github.com/lc) - gau
- [hakluke](https://github.com/hakluke) - hakrawler

## License

This tool is provided as-is for educational and authorized security testing purposes.

## Disclaimer

The authors are not responsible for misuse of this tool. Always ensure you have proper authorization before testing any application.

---

**Happy (Ethical) Hunting!** 🎯

For questions or issues, please ensure you're using the tool responsibly and within legal boundaries.
