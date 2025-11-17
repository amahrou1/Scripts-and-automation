package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds application configuration
type Config struct {
	InputFile      string
	OutputDir      string
	Threads        int
	DiscordWebhook string
	VTAPIKey       string
	Verbose        bool
}

// Vulnerability represents a found vulnerability
type Vulnerability struct {
	URL           string
	OriginalURL   string
	Parameter     string
	Payload       string
	Reason        string
	StatusCode    int
	RedirectChain []string
}

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
)

var (
	config          Config
	seenVulns       = make(map[string]bool)
	seenVulnsMutex  sync.Mutex
	vulnerabilities []Vulnerability
	vulnsMutex      sync.Mutex
	httpClient      *http.Client
)

// Test payloads
var testPayloads = []string{
	"https://evil.com",
	"http://evil.com",
	"//evil.com",
	"///evil.com",
	"////evil.com",
	"https://evil.com/",
	"https:evil.com",
	"//google.com",
	"///google.com",
	"https://evil.com%00",
	"https://evil.com%0d%0a",
	"https://evil.com\\",
	"https:\\evil.com",
	"https://legitimate.com@evil.com",
	"https://evil.com.",
	"javascript:alert(document.domain)",
	"https://redirect-test.com",
}

// Redirect parameters
var redirectParams = []string{
	"url", "redirect", "redir", "return", "next", "destination", "dest",
	"continue", "view", "target", "to", "out", "link", "site", "location",
	"domain", "reference", "ref", "path", "window", "uri", "forward",
	"forwardurl", "goto", "go", "ReturnUrl", "redirect_url", "redirect_uri",
	"redirectUrl", "redirectUri", "return_url", "returnUrl", "next_url",
	"nextUrl", "callback", "callback_url", "callbackUrl",
}

// Test domains to check for
var testDomains = []string{"evil.com", "google.com", "redirect-test.com"}

func init() {
	// Suppress HTTP client error logs (like "Unsolicited response")
	log.SetOutput(io.Discard)

	// Create HTTP client with timeout and no redirect following
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

func main() {
	printBanner()

	// Parse command line flags
	flag.StringVar(&config.InputFile, "l", "", "Input file containing URLs (required)")
	flag.StringVar(&config.OutputDir, "o", "results", "Output directory")
	flag.IntVar(&config.Threads, "t", 100, "Number of concurrent threads")
	flag.StringVar(&config.DiscordWebhook, "w", "", "Discord webhook URL")
	flag.StringVar(&config.VTAPIKey, "k", "", "VirusTotal API key")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.Parse()

	if config.InputFile == "" {
		fmt.Println(ColorRed + "[!] Input file is required" + ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	// Create output directory
	os.MkdirAll(config.OutputDir, 0755)

	fmt.Printf("%s[*] Input file: %s%s\n", ColorBlue, config.InputFile, ColorReset)
	fmt.Printf("%s[*] Threads: %d%s\n", ColorBlue, config.Threads, ColorReset)
	fmt.Printf("%s[*] Output directory: %s%s\n\n", ColorBlue, config.OutputDir, ColorReset)

	// Read URLs from file
	urls, err := readURLsFromFile(config.InputFile)
	if err != nil {
		fmt.Printf("%s[!] Error reading file: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	// Filter URLs - only test those with parameters
	filteredURLs := filterURLsWithParams(urls)
	fmt.Printf("%s[*] Loaded %d URLs total%s\n", ColorBlue, len(urls), ColorReset)
	fmt.Printf("%s[*] URLs with parameters: %d (%.1f%%)%s\n\n", ColorGreen, len(filteredURLs),
		float64(len(filteredURLs))/float64(len(urls))*100, ColorReset)

	if len(filteredURLs) == 0 {
		fmt.Printf("%s[!] No URLs with parameters found. Exiting.%s\n", ColorYellow, ColorReset)
		os.Exit(0)
	}

	// Start testing
	startTime := time.Now()
	testURLs(filteredURLs)

	// Print summary
	elapsed := time.Since(startTime)
	fmt.Printf("\n%s[✓] Scan completed in %s%s\n", ColorGreen, elapsed.Round(time.Second), ColorReset)
	fmt.Printf("%s[*] Total vulnerabilities found: %d%s\n", ColorGreen, len(vulnerabilities), ColorReset)

	// Save results
	saveResults()
}

func printBanner() {
	banner := `
  ___                   ____          _ _               _
 / _ \ _ __   ___ _ __ |  _ \ ___  __| (_)_ __ ___  ___| |_
| | | | '_ \ / _ \ '_ \| |_) / _ \/ _` + "`" + ` | | '__/ _ \/ __| __|
| |_| | |_) |  __/ | | |  _ <  __/ (_| | | | |  __/ (__| |_
 \___/| .__/ \___|_| |_|_| \_\___|\__,_|_|_|  \___|\___|\__|
      |_|    Scanner v2.0 (Go Edition)
`
	fmt.Println(ColorBlue + banner + ColorReset)
}

func readURLsFromFile(filename string) ([]string, error) {
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
			// Normalize URL - add http:// if missing
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
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
		// Only include URLs that have query parameters
		if len(parsed.Query()) > 0 {
			filtered = append(filtered, u)
		}
	}
	return filtered
}

func testURLs(urls []string) {
	// Use semaphore pattern for concurrency control
	sem := make(chan struct{}, config.Threads)
	var wg sync.WaitGroup

	// Progress tracking
	var processed int64
	total := int64(len(urls))
	progressInterval := total / 100
	if progressInterval < 100 {
		progressInterval = 100
	}

	startTime := time.Now()

	for _, targetURL := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			testURL(u)

			// Update progress
			current := atomic.AddInt64(&processed, 1)
			if current%progressInterval == 0 || current == total {
				elapsed := time.Since(startTime)
				rate := float64(current) / elapsed.Seconds()
				remaining := time.Duration(float64(total-current)/rate) * time.Second

				fmt.Printf("\r%s[*] Progress: %d/%d (%.1f%%) | Found: %d | Rate: %.0f URL/s | ETA: %s%s",
					ColorYellow, current, total, float64(current)/float64(total)*100,
					len(vulnerabilities), rate, remaining.Round(time.Second), ColorReset)
			}
		}(targetURL)
	}

	wg.Wait()
	fmt.Println() // New line after progress
}

func testURL(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	if len(params) == 0 {
		return
	}

	// Find redirect parameters
	redirectParamsFound := []string{}
	for param := range params {
		for _, redirectParam := range redirectParams {
			if strings.EqualFold(param, redirectParam) {
				redirectParamsFound = append(redirectParamsFound, param)
				break
			}
		}
	}

	// If no known redirect params, test all params
	if len(redirectParamsFound) == 0 {
		for param := range params {
			redirectParamsFound = append(redirectParamsFound, param)
		}
	}

	// Test each parameter
	for _, param := range redirectParamsFound {
		// Create unique key
		uniqueKey := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, param)

		seenVulnsMutex.Lock()
		if seenVulns[uniqueKey] {
			seenVulnsMutex.Unlock()
			continue
		}
		seenVulnsMutex.Unlock()

		// Test with different payloads
		for _, payload := range testPayloads {
			// Create test URL
			newParams := url.Values{}
			for k, v := range params {
				newParams[k] = v
			}
			newParams.Set(param, payload)

			testURLStr := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, newParams.Encode())

			// Make request
			if isVulnerable, reason := checkOpenRedirect(testURLStr, targetURL, payload); isVulnerable {
				// Mark as seen
				seenVulnsMutex.Lock()
				seenVulns[uniqueKey] = true
				seenVulnsMutex.Unlock()

				vuln := Vulnerability{
					URL:         testURLStr,
					OriginalURL: targetURL,
					Parameter:   param,
					Payload:     payload,
					Reason:      reason,
				}

				// Add to results
				vulnsMutex.Lock()
				vulnerabilities = append(vulnerabilities, vuln)
				vulnsMutex.Unlock()

				// Print finding
				fmt.Printf("%s[VULNERABLE]%s %s\n", ColorRed, ColorReset, testURLStr)
				fmt.Printf("  └─ Parameter: %s | Payload: %s | Reason: %s\n", param, payload, reason)

				// Send Discord notification
				if config.DiscordWebhook != "" {
					go sendDiscordNotification(vuln)
				}

				break // Found vulnerability for this parameter
			}
		}
	}
}

func checkOpenRedirect(testURL, originalURL, payload string) (bool, string) {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false, ""
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// Extract the domain from our payload to check if redirect goes there
	payloadDomain := extractDomainFromPayload(payload)

	// Check HTTP redirects (3xx status codes)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			return false, ""
		}

		// Parse redirect location
		redirectURL, err := url.Parse(location)
		if err != nil {
			// Try simple string matching for malformed URLs
			locationLower := strings.ToLower(location)
			if payloadDomain != "" && strings.Contains(locationLower, payloadDomain) {
				return true, fmt.Sprintf("HTTP %d redirect contains payload domain: %s", resp.StatusCode, location)
			}
			return false, ""
		}

		// Handle protocol-relative URLs (//evil.com)
		if strings.HasPrefix(location, "//") {
			redirectDomain := strings.ToLower(redirectURL.Host)
			if payloadDomain != "" && (redirectDomain == payloadDomain || strings.HasSuffix(redirectDomain, "."+payloadDomain)) {
				return true, fmt.Sprintf("Protocol-relative redirect to payload domain: %s", location)
			}
		}

		// Handle relative redirects (not open redirects)
		if strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
			return false, ""
		}

		// Get redirect domain
		redirectDomain := strings.ToLower(redirectURL.Host)
		if redirectDomain == "" {
			return false, ""
		}

		// Check if redirect goes to our payload domain
		if payloadDomain != "" {
			if redirectDomain == payloadDomain || strings.HasSuffix(redirectDomain, "."+payloadDomain) {
				return true, fmt.Sprintf("HTTP %d redirect to payload domain: %s (redirected to: %s)", resp.StatusCode, payloadDomain, location)
			}
		}

		// Also check if redirect URL contains the full payload (for exact matches)
		locationLower := strings.ToLower(location)
		payloadLower := strings.ToLower(payload)
		// Remove protocol and slashes for comparison
		payloadClean := strings.TrimPrefix(payloadLower, "https://")
		payloadClean = strings.TrimPrefix(payloadClean, "http://")
		payloadClean = strings.TrimPrefix(payloadClean, "//")
		payloadClean = strings.TrimSuffix(payloadClean, "/")

		if payloadClean != "" && strings.Contains(locationLower, payloadClean) {
			return true, fmt.Sprintf("HTTP %d redirect contains payload: %s", resp.StatusCode, location)
		}
	}

	// Check for meta refresh and JavaScript redirects in 200 responses
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
		if err != nil {
			return false, ""
		}

		bodyStr := strings.ToLower(string(body))

		// Check meta refresh
		metaRefreshRegex := regexp.MustCompile(`<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"']+)`)
		matches := metaRefreshRegex.FindStringSubmatch(bodyStr)
		if len(matches) > 1 {
			redirectURL := matches[1]
			if parsedRedir, err := url.Parse(redirectURL); err == nil {
				redirDomain := strings.ToLower(parsedRedir.Host)

				// Check if meta refresh goes to payload domain
				if payloadDomain != "" && (redirDomain == payloadDomain || strings.HasSuffix(redirDomain, "."+payloadDomain)) {
					return true, fmt.Sprintf("Meta refresh redirect to payload domain: %s", redirectURL)
				}
			}

			// Check if meta refresh contains payload
			if payloadDomain != "" && strings.Contains(strings.ToLower(redirectURL), payloadDomain) {
				return true, fmt.Sprintf("Meta refresh contains payload domain: %s", redirectURL)
			}
		}

		// Check JavaScript redirects
		jsPatterns := []string{
			`window\.location\s*=\s*["']([^"']+)["']`,
			`window\.location\.href\s*=\s*["']([^"']+)["']`,
			`document\.location\s*=\s*["']([^"']+)["']`,
			`location\.href\s*=\s*["']([^"']+)["']`,
		}

		for _, pattern := range jsPatterns {
			jsRegex := regexp.MustCompile(pattern)
			matches := jsRegex.FindStringSubmatch(bodyStr)
			if len(matches) > 1 {
				redirectURL := matches[1]
				if parsedRedir, err := url.Parse(redirectURL); err == nil {
					redirDomain := strings.ToLower(parsedRedir.Host)

					// Check if JS redirect goes to payload domain
					if payloadDomain != "" && (redirDomain == payloadDomain || strings.HasSuffix(redirDomain, "."+payloadDomain)) {
						return true, fmt.Sprintf("JavaScript redirect to payload domain: %s", redirectURL)
					}
				}

				// Check if JS redirect contains payload
				if payloadDomain != "" && strings.Contains(strings.ToLower(redirectURL), payloadDomain) {
					return true, fmt.Sprintf("JavaScript redirect contains payload domain: %s", redirectURL)
				}
			}
		}
	}

	return false, ""
}

// extractDomainFromPayload extracts the domain from various payload formats
func extractDomainFromPayload(payload string) string {
	payload = strings.TrimSpace(payload)
	payloadLower := strings.ToLower(payload)

	// Skip non-URL payloads
	if strings.HasPrefix(payloadLower, "javascript:") ||
		strings.HasPrefix(payloadLower, "data:") {
		return ""
	}

	// Handle protocol-relative URLs (//evil.com)
	if strings.HasPrefix(payload, "//") {
		payload = "http:" + payload
	}

	// Add http:// if no protocol
	if !strings.HasPrefix(payloadLower, "http://") && !strings.HasPrefix(payloadLower, "https://") {
		payload = "http://" + payload
	}

	// Parse URL
	parsed, err := url.Parse(payload)
	if err != nil {
		return ""
	}

	domain := strings.ToLower(parsed.Host)
	// Remove port if present
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	return domain
}

func sendDiscordNotification(vuln Vulnerability) {
	if config.DiscordWebhook == "" {
		return
	}

	// Rate limiting
	time.Sleep(500 * time.Millisecond)

	embed := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "🚨 Open Redirect Vulnerability Found!",
				"description": fmt.Sprintf("**URL:** %s\n**Parameter:** %s", vuln.OriginalURL, vuln.Parameter),
				"color":       15158332,
				"fields": []map[string]interface{}{
					{
						"name":   "Vulnerable URL",
						"value":  fmt.Sprintf("```%s```", truncateString(vuln.URL, 1000)),
						"inline": false,
					},
					{
						"name":   "Payload",
						"value":  fmt.Sprintf("`%s`", vuln.Payload),
						"inline": true,
					},
					{
						"name":   "Detection Method",
						"value":  fmt.Sprintf("`%s`", vuln.Reason),
						"inline": false,
					},
				},
				"footer": map[string]string{
					"text": "Open Redirect Scanner v2.0",
				},
			},
		},
	}

	jsonData, _ := json.Marshal(embed)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(config.DiscordWebhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		if config.Verbose {
			fmt.Printf("%s[!] Discord notification failed: %v%s\n", ColorYellow, err, ColorReset)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		if config.Verbose {
			fmt.Printf("%s[✓] Discord notification sent%s\n", ColorGreen, ColorReset)
		}
	}
}

func saveResults() {
	if len(vulnerabilities) == 0 {
		fmt.Printf("%s[*] No vulnerabilities found%s\n", ColorYellow, ColorReset)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s/vulnerabilities_%s.txt", config.OutputDir, timestamp)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("%s[!] Error creating output file: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "# Open Redirect Vulnerabilities Found\n")
	fmt.Fprintf(writer, "# Scan Date: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	for _, vuln := range vulnerabilities {
		fmt.Fprintf(writer, "[VULNERABLE] %s\n", vuln.URL)
		fmt.Fprintf(writer, "  Original URL: %s\n", vuln.OriginalURL)
		fmt.Fprintf(writer, "  Parameter: %s\n", vuln.Parameter)
		fmt.Fprintf(writer, "  Payload: %s\n", vuln.Payload)
		fmt.Fprintf(writer, "  Reason: %s\n\n", vuln.Reason)
	}

	writer.Flush()
	fmt.Printf("%s[*] Results saved to: %s%s\n", ColorBlue, filename, ColorReset)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
