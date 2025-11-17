# XSS Scanner - Reflected XSS Vulnerability Scanner

A high-performance, context-aware reflected XSS scanner written in Go. Designed for bug bounty hunters and security researchers.

## Features

- ✅ **Context-Aware Detection** - Identifies injection context (HTML, JavaScript, Attribute, URL)
- ✅ **Marker-Based Tracking** - Uses unique markers to find reflection points accurately
- ✅ **Multi-Level Payloads** - 60+ payloads including basic, encoded, and WAF bypasses
- ✅ **False Positive Reduction** - Validates payload execution, not just reflection
- ✅ **Discord Notifications** - Real-time alerts for discovered vulnerabilities
- ✅ **High Performance** - Concurrent scanning with progress tracking
- ✅ **Smart Filtering** - Only tests URLs with parameters

## How It Works

1. **Marker Injection** - Injects unique marker in each parameter
2. **Reflection Detection** - Checks if marker reflects in response
3. **Context Analysis** - Determines where reflection occurs (HTML, JS, etc.)
4. **Payload Generation** - Selects context-appropriate payloads
5. **Validation** - Verifies payload is exploitable (not encoded/filtered)
6. **Reporting** - Alerts via terminal and Discord

## Installation

### Quick Install

```bash
./install.sh
```

### Manual Install

```bash
# Make sure Go is installed (1.19+)
cd xss-scanner
go build -o xss-scanner main.go
chmod +x xss-scanner
```

## Usage

### Basic Usage

```bash
./xss-scanner -f urls.txt
```

### With Discord Notifications

```bash
./xss-scanner -f urls.txt -discord https://discord.com/api/webhooks/YOUR_WEBHOOK
```

### With Custom Concurrency

```bash
./xss-scanner -f urls.txt -c 100 -t 15
```

### With Output Directory

```bash
# Save results to a directory
./xss-scanner -f urls.txt -o results

# With Discord notifications and output directory
./xss-scanner -f urls.txt -o xss-findings -discord https://discord.com/api/webhooks/...
```

### Options

```
-f string
    File containing URLs to test (required)
-c int
    Number of concurrent requests (default 50)
-t int
    HTTP timeout in seconds (default 10)
-discord string
    Discord webhook URL for notifications
-o string
    Output directory to save results (optional)
```

## Input Format

The scanner expects a file with one URL per line. URLs must have parameters:

```
https://example.com/page?id=123
https://test.com/search?q=test&page=1
https://app.example.com/profile?user=admin
```

**Note**: Only URLs with query parameters will be tested. URLs without parameters will be skipped.

## Configuration

You can store your Discord webhook in `../config.sh`:

```bash
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK"
```

## Output Files

When you use the `-o` flag, the scanner creates a directory with detailed vulnerability reports:

### Directory Structure

```
results/
├── summary.txt                           # Quick overview of all vulnerabilities
├── summary.json                          # JSON format for easy parsing
├── 20241117-103045_example.com_q_HTML_Body.txt
├── 20241117-103045_example.com_q_HTML_Body.json
├── 20241117-103112_test.com_id_JavaScript_String.txt
└── 20241117-103112_test.com_id_JavaScript_String.json
```

### File Types

**1. Individual Vulnerability Reports (.txt)**
```
XSS Vulnerability Report
========================
Timestamp: 2024-11-17T10:30:45Z
URL: https://example.com/search?q=test
Parameter: q
Context: HTML Body
Payload: <img src=x onerror=alert(1)>

Reproduction Steps:
1. Navigate to: https://example.com/search?q=test
2. Parameter 'q' is vulnerable to XSS
3. Test payload: <img src=x onerror=alert(1)>

Severity: High (Reflected XSS)
```

**2. Individual Vulnerability Reports (.json)**
```json
{
  "timestamp": "2024-11-17T10:30:45Z",
  "url": "https://example.com/search?q=test",
  "parameter": "q",
  "context": "HTML Body",
  "payload": "<img src=x onerror=alert(1)>"
}
```

**3. Summary Files**

`summary.txt` - Quick overview:
```
[2024-11-17 10:30:45] https://example.com/search?q=test | Param: q | Context: HTML Body | Payload: <img src=x onerror=alert(1)>
[2024-11-17 10:31:12] https://test.com/page?id=123 | Param: id | Context: JavaScript String | Payload: ";alert(1)//
```

`summary.json` - All vulnerabilities in JSON array:
```json
[
  {
    "timestamp": "2024-11-17T10:30:45Z",
    "url": "https://example.com/search?q=test",
    "parameter": "q",
    "context": "HTML Body",
    "payload": "<img src=x onerror=alert(1)>"
  },
  {
    "timestamp": "2024-11-17T10:31:12Z",
    "url": "https://test.com/page?id=123",
    "parameter": "id",
    "context": "JavaScript String",
    "payload": "\";alert(1)//"
  }
]
```

### Use Cases

- **Bug Bounty Reports**: Use individual .txt files as report templates
- **Automation**: Parse summary.json for integration with other tools
- **Evidence**: Keep detailed records of all findings
- **Collaboration**: Share results directory with team members

## Detection Contexts

The scanner detects and exploits 6 different injection contexts:

### 1. HTML Body Context
```html
<div>YOUR_INPUT</div>
```
Payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`

### 2. HTML Attribute Context
```html
<input value="YOUR_INPUT">
```
Payloads: `" onfocus="alert(1)" autofocus="`

### 3. JavaScript String Context
```javascript
var x = "YOUR_INPUT";
```
Payloads: `";alert(1)//`

### 4. JavaScript Context
```javascript
var x = YOUR_INPUT;
```
Payloads: `alert(1)`, `[1].find(alert)`

### 5. URL Context
```html
<a href="YOUR_INPUT">
```
Payloads: `javascript:alert(1)`

### 6. HTML Comment (Skipped)
```html
<!-- YOUR_INPUT -->
```
Not exploitable - automatically skipped

## Payload Database

The scanner includes 60+ carefully crafted payloads:

- **Basic Payloads** - Standard XSS vectors
- **Event Handlers** - onload, onerror, onfocus, etc.
- **WAF Bypasses** - Case mixing, encoding, obfuscation
- **Advanced Vectors** - iframe srcdoc, object data, etc.
- **Polyglot Payloads** - Work in multiple contexts

## False Positive Reduction

The scanner reduces false positives by:

1. ✅ Checking if payload is HTML-encoded (rejects `&lt;script&gt;`)
2. ✅ Verifying context-appropriate exploitation
3. ✅ Confirming payload structure is intact
4. ✅ Skipping non-exploitable contexts (comments)
5. ✅ Using marker-based reflection tracking

## Output Example

```
[+] Loaded 1000 URLs
[+] Found 234 URLs with parameters
[+] Discord notifications enabled
[+] Results will be saved to: results
[*] Progress: 234/234 (100.0%) | Rate: 45 URLs/s | Reflected: 12 | Vulnerable: 3 | ETA: 0s

[!] VULNERABLE: https://example.com/search?q=test
    Parameter: q
    Context: HTML Body
    Payload: <img src=x onerror=alert(1)>

[+] Scan complete!
[+] Total URLs: 234
[+] Tested: 234
[+] Reflected: 12
[+] Vulnerable: 3
[+] Time taken: 5s
```

When using the `-o` flag, all vulnerabilities are saved to individual files plus summary files in the specified directory.

## Performance

- **Speed**: 40-100 URLs/second (depends on target response time)
- **Concurrency**: Adjustable (default 50 concurrent requests)
- **Memory**: Low memory footprint (~50MB)
- **Scalability**: Can handle 100K+ URLs

## Tips for Bug Bounty Hunting

1. **Gather URLs with parameters** - Use tools like:
   - waybackurls
   - gau (GetAllURLs)
   - katana
   - paramspider

2. **Filter for interesting parameters**:
   ```bash
   cat urls.txt | grep -E "q=|search=|query=|url=|redirect=|return="
   ```

3. **Test different parameter combinations**

4. **Use Discord notifications** - Get alerts while scanning runs

5. **Adjust concurrency** - Higher for fast targets, lower for slow ones

## Comparison with Other Tools

| Feature | This Scanner | Dalfox | XSStrike |
|---------|-------------|---------|----------|
| Language | Go | Go | Python |
| Context Detection | ✅ Yes | ✅ Yes | ✅ Yes |
| Marker-based | ✅ Yes | ✅ Yes | ✅ Yes |
| False Positive Reduction | ✅ High | ✅ High | ✅ High |
| Discord Alerts | ✅ Yes | ❌ No | ❌ No |
| Speed | ⚡ Fast | ⚡ Fast | 🐌 Slow |
| Easy Setup | ✅ Simple | ⚠️ Complex | ⚠️ Complex |

## Limitations

- **Client-side XSS**: Does not detect DOM-based XSS requiring browser execution
- **Stored XSS**: Only detects reflected XSS, not stored/persistent
- **JavaScript-heavy apps**: Limited support for Single Page Applications (SPAs)
- **WAF Detection**: No automatic WAF fingerprinting

## Troubleshooting

### No vulnerabilities found

- Ensure URLs have parameters
- Try increasing timeout: `-t 20`
- Check if target has WAF/filtering
- Verify URLs are accessible

### Too many false positives

- The scanner already has strong FP reduction
- Check if payloads are actually exploitable
- Verify in browser to confirm

### Scanner too slow

- Increase concurrency: `-c 100`
- Reduce timeout: `-t 5`
- Filter URLs to only test interesting parameters

## Contributing

Improvements welcome! Areas for contribution:

- Additional WAF bypass payloads
- Better context detection
- DOM XSS support (with headless browser)
- Custom payload file support

## Disclaimer

This tool is for authorized security testing only. Always obtain proper permission before testing any website. Unauthorized testing is illegal.

## Author

Created for bug bounty hunting on Intigriti and HackerOne platforms.

## License

MIT License - Free for personal and commercial use.
