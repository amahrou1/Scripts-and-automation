#!/bin/bash

# Open Redirect Scanner
# Author: Bug Bounty Toolkit
# Description: Automated open redirect vulnerability scanner using multiple OSINT sources

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
  ___                   ____          _ _               _
 / _ \ _ __   ___ _ __ |  _ \ ___  __| (_)_ __ ___  ___| |_
| | | | '_ \ / _ \ '_ \| |_) / _ \/ _` | | '__/ _ \/ __| __|
| |_| | |_) |  __/ | | |  _ <  __/ (_| | | | |  __/ (__| |_
 \___/| .__/ \___|_| |_|_| \_\___|\__,_|_|_|  \___|\___|\__|
      |_|    Scanner v1.0
EOF
echo -e "${NC}"

# Default values
INPUT_FILE=""
OUTPUT_DIR="open-redirect-results"
THREADS=50
VERBOSE=false

# Help function
usage() {
    echo -e "${GREEN}Usage:${NC}"
    echo "  $0 -l subdomains.txt [OPTIONS]"
    echo ""
    echo -e "${GREEN}Options:${NC}"
    echo "  -l, --list        Input file containing subdomains (required)"
    echo "  -o, --output      Output directory (default: open-redirect-results)"
    echo "  -t, --threads     Number of threads (default: 50)"
    echo "  -v, --verbose     Verbose output"
    echo "  -h, --help        Show this help message"
    echo ""
    echo -e "${GREEN}Example:${NC}"
    echo "  $0 -l subdomains.txt -o results -t 100"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--list)
            INPUT_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Check if input file is provided
if [[ -z "$INPUT_FILE" ]]; then
    echo -e "${RED}Error: Input file is required${NC}"
    usage
fi

# Check if input file exists
if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}Error: File '$INPUT_FILE' not found${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Output files
URLS_FILE="$OUTPUT_DIR/urls_collected_$TIMESTAMP.txt"
FILTERED_URLS="$OUTPUT_DIR/potential_redirects_$TIMESTAMP.txt"
VULNERABLE_FILE="$OUTPUT_DIR/vulnerable_$TIMESTAMP.txt"
LOG_FILE="$OUTPUT_DIR/scan_log_$TIMESTAMP.log"

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log "${GREEN}[+] Starting Open Redirect Scanner${NC}"
log "${BLUE}[*] Input file: $INPUT_FILE${NC}"
log "${BLUE}[*] Output directory: $OUTPUT_DIR${NC}"
log "${BLUE}[*] Threads: $THREADS${NC}"
echo ""

# Step 1: Validate live subdomains
log "${YELLOW}[1/6] Validating live subdomains with httpx...${NC}"
LIVE_HOSTS="$OUTPUT_DIR/live_hosts_$TIMESTAMP.txt"

if command -v httpx &> /dev/null; then
    cat "$INPUT_FILE" | httpx -silent -threads "$THREADS" -o "$LIVE_HOSTS" -mc 200,201,301,302,303,307,308,401,403,405
    LIVE_COUNT=$(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0)
    log "${GREEN}[✓] Found $LIVE_COUNT live hosts${NC}"
else
    log "${YELLOW}[!] httpx not found, using input file directly${NC}"
    cp "$INPUT_FILE" "$LIVE_HOSTS"
fi
echo ""

# Step 2: Gather URLs from multiple sources
log "${YELLOW}[2/6] Gathering URLs from multiple sources...${NC}"

# Initialize empty URLs file
> "$URLS_FILE"

# 2a. Wayback Machine
if command -v waybackurls &> /dev/null; then
    log "${BLUE}  [*] Fetching from Wayback Machine...${NC}"
    cat "$LIVE_HOSTS" | waybackurls | tee -a "$URLS_FILE" > /dev/null
    WB_COUNT=$(wc -l < "$URLS_FILE" 2>/dev/null || echo 0)
    log "${GREEN}  [✓] Wayback URLs: $WB_COUNT${NC}"
fi

# 2b. GAU (GetAllUrls)
if command -v gau &> /dev/null; then
    log "${BLUE}  [*] Fetching from GAU (Common Crawl, Wayback, etc.)...${NC}"
    GAU_TEMP="$OUTPUT_DIR/gau_temp.txt"
    cat "$LIVE_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg,jpeg,gif,css,ico 2>/dev/null | tee "$GAU_TEMP" > /dev/null
    cat "$GAU_TEMP" >> "$URLS_FILE"
    rm -f "$GAU_TEMP"
fi

# 2c. Katana (web crawler)
if command -v katana &> /dev/null; then
    log "${BLUE}  [*] Crawling with Katana...${NC}"
    KATANA_TEMP="$OUTPUT_DIR/katana_temp.txt"
    cat "$LIVE_HOSTS" | katana -silent -d 3 -jc -kf all -c "$THREADS" -o "$KATANA_TEMP" 2>/dev/null
    cat "$KATANA_TEMP" >> "$URLS_FILE" 2>/dev/null
    rm -f "$KATANA_TEMP"
fi

# 2d. Hakrawler
if command -v hakrawler &> /dev/null; then
    log "${BLUE}  [*] Crawling with Hakrawler...${NC}"
    HAKRAWLER_TEMP="$OUTPUT_DIR/hakrawler_temp.txt"
    cat "$LIVE_HOSTS" | hakrawler -depth 2 -plain -t "$THREADS" 2>/dev/null | tee "$HAKRAWLER_TEMP" > /dev/null
    cat "$HAKRAWLER_TEMP" >> "$URLS_FILE"
    rm -f "$HAKRAWLER_TEMP"
fi

# Remove duplicates and sort
sort -u "$URLS_FILE" -o "$URLS_FILE"
TOTAL_URLS=$(wc -l < "$URLS_FILE" 2>/dev/null || echo 0)
log "${GREEN}[✓] Total unique URLs collected: $TOTAL_URLS${NC}"
echo ""

# Step 3: Filter URLs with potential redirect parameters
log "${YELLOW}[3/6] Filtering URLs with potential redirect parameters...${NC}"

if command -v gf &> /dev/null; then
    # Use gf patterns for redirect
    cat "$URLS_FILE" | gf redirect 2>/dev/null > "$FILTERED_URLS"

    # Also manually filter for common redirect parameters
    cat "$URLS_FILE" | grep -iE "(url=|redirect=|redir=|return=|next=|destination=|dest=|continue=|view=|target=|to=|out=|link=|site=|location=|domain=|reference=|ref=|path=|window=|uri=|forward=|forwardurl=|goto=|go=)" >> "$FILTERED_URLS"
else
    # Manual filtering if gf is not available
    log "${YELLOW}[!] gf not found, using manual filtering${NC}"
    cat "$URLS_FILE" | grep -iE "(url=|redirect=|redir=|return=|next=|destination=|dest=|continue=|view=|target=|to=|out=|link=|site=|location=|domain=|reference=|ref=|path=|window=|uri=|forward=|forwardurl=|goto=|go=)" > "$FILTERED_URLS"
fi

sort -u "$FILTERED_URLS" -o "$FILTERED_URLS"
FILTERED_COUNT=$(wc -l < "$FILTERED_URLS" 2>/dev/null || echo 0)
log "${GREEN}[✓] Potential redirect URLs: $FILTERED_COUNT${NC}"
echo ""

# Step 4: Check if URLs are live and responsive
log "${YELLOW}[4/6] Validating filtered URLs...${NC}"
VALID_URLS="$OUTPUT_DIR/valid_urls_$TIMESTAMP.txt"

if command -v httpx &> /dev/null && [[ $FILTERED_COUNT -gt 0 ]]; then
    cat "$FILTERED_URLS" | httpx -silent -threads "$THREADS" -mc 200,201,301,302,303,307,308 -o "$VALID_URLS"
    VALID_COUNT=$(wc -l < "$VALID_URLS" 2>/dev/null || echo 0)
    log "${GREEN}[✓] Valid responsive URLs: $VALID_COUNT${NC}"
else
    cp "$FILTERED_URLS" "$VALID_URLS"
    VALID_COUNT=$FILTERED_COUNT
fi
echo ""

# Step 5: Test for open redirects
log "${YELLOW}[5/6] Testing for open redirect vulnerabilities...${NC}"

if [[ $VALID_COUNT -eq 0 ]]; then
    log "${YELLOW}[!] No URLs to test${NC}"
else
    # Use Python script for testing
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$SCRIPT_DIR/test-redirects.py" ]]; then
        python3 "$SCRIPT_DIR/test-redirects.py" -l "$VALID_URLS" -o "$VULNERABLE_FILE" -t "$THREADS"
    else
        log "${RED}[!] test-redirects.py not found, skipping vulnerability testing${NC}"
        log "${YELLOW}[!] Please run the installation script or place test-redirects.py in the same directory${NC}"
    fi
fi
echo ""

# Step 6: Summary
log "${YELLOW}[6/6] Scan Summary${NC}"
log "${BLUE}═══════════════════════════════════════════════${NC}"
log "${GREEN}Live hosts found:        $(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0)${NC}"
log "${GREEN}Total URLs collected:    $TOTAL_URLS${NC}"
log "${GREEN}Filtered URLs:           $FILTERED_COUNT${NC}"
log "${GREEN}Valid URLs tested:       $VALID_COUNT${NC}"

if [[ -f "$VULNERABLE_FILE" ]]; then
    VULN_COUNT=$(grep -c "VULNERABLE" "$VULNERABLE_FILE" 2>/dev/null || echo 0)
    log "${GREEN}Vulnerabilities found:   $VULN_COUNT${NC}"

    if [[ $VULN_COUNT -gt 0 ]]; then
        log ""
        log "${RED}[!] VULNERABLE URLs:${NC}"
        grep "VULNERABLE" "$VULNERABLE_FILE" | while read line; do
            log "${RED}  → $line${NC}"
        done
    fi
fi

log "${BLUE}═══════════════════════════════════════════════${NC}"
log ""
log "${GREEN}[✓] Scan completed!${NC}"
log "${BLUE}[*] Results saved in: $OUTPUT_DIR${NC}"
log "${BLUE}[*] Log file: $LOG_FILE${NC}"

if [[ -f "$VULNERABLE_FILE" ]] && [[ $VULN_COUNT -gt 0 ]]; then
    log "${BLUE}[*] Vulnerable URLs: $VULNERABLE_FILE${NC}"
    log ""
    log "${YELLOW}[!] Remember to verify findings manually before reporting!${NC}"
fi
