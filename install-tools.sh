#!/bin/bash

# Installation script for Open Redirect Scanner dependencies
# For Ubuntu/Debian systems

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════╗
║   Open Redirect Scanner - Dependency Installer   ║
╚═══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root for system packages
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[!] Running as root. System packages will be installed.${NC}"
else
   echo -e "${YELLOW}[!] Not running as root. You may need sudo for system packages.${NC}"
   echo -e "${YELLOW}[!] Go tools will be installed in ~/go/bin${NC}"
fi

echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update and install system dependencies
echo -e "${BLUE}[*] Installing system dependencies...${NC}"
if command_exists apt-get; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq git curl wget python3 python3-pip golang-go jq 2>/dev/null
    echo -e "${GREEN}[✓] System dependencies installed${NC}"
else
    echo -e "${YELLOW}[!] apt-get not found. Please install git, curl, wget, python3, python3-pip, and golang manually.${NC}"
fi

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
if command_exists pip3; then
    pip3 install -q requests urllib3 >/dev/null 2>&1
    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
else
    echo -e "${RED}[✗] pip3 not found. Please install pip3 first.${NC}"
fi

# Set up Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH/bin

# Add to .bashrc if not already there
if ! grep -q "export GOPATH=\$HOME/go" ~/.bashrc; then
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    echo -e "${GREEN}[✓] Added Go paths to .bashrc${NC}"
fi

echo ""
echo -e "${BLUE}[*] Installing Go-based security tools...${NC}"
echo ""

# httpx - HTTP toolkit
if ! command_exists httpx; then
    echo -e "${YELLOW}[1/8] Installing httpx...${NC}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1
    if command_exists httpx; then
        echo -e "${GREEN}[✓] httpx installed${NC}"
    else
        echo -e "${RED}[✗] httpx installation failed${NC}"
    fi
else
    echo -e "${GREEN}[1/8] httpx already installed${NC}"
fi

# waybackurls - Wayback Machine URL fetcher
if ! command_exists waybackurls; then
    echo -e "${YELLOW}[2/8] Installing waybackurls...${NC}"
    go install github.com/tomnomnom/waybackurls@latest >/dev/null 2>&1
    if command_exists waybackurls; then
        echo -e "${GREEN}[✓] waybackurls installed${NC}"
    else
        echo -e "${RED}[✗] waybackurls installation failed${NC}"
    fi
else
    echo -e "${GREEN}[2/8] waybackurls already installed${NC}"
fi

# gau - GetAllURLs
if ! command_exists gau; then
    echo -e "${YELLOW}[3/8] Installing gau...${NC}"
    go install github.com/lc/gau/v2/cmd/gau@latest >/dev/null 2>&1
    if command_exists gau; then
        echo -e "${GREEN}[✓] gau installed${NC}"
    else
        echo -e "${RED}[✗] gau installation failed${NC}"
    fi
else
    echo -e "${GREEN}[3/8] gau already installed${NC}"
fi

# katana - Web crawler
if ! command_exists katana; then
    echo -e "${YELLOW}[4/8] Installing katana...${NC}"
    go install github.com/projectdiscovery/katana/cmd/katana@latest >/dev/null 2>&1
    if command_exists katana; then
        echo -e "${GREEN}[✓] katana installed${NC}"
    else
        echo -e "${RED}[✗] katana installation failed${NC}"
    fi
else
    echo -e "${GREEN}[4/8] katana already installed${NC}"
fi

# hakrawler - Web crawler
if ! command_exists hakrawler; then
    echo -e "${YELLOW}[5/8] Installing hakrawler...${NC}"
    go install github.com/hakluke/hakrawler@latest >/dev/null 2>&1
    if command_exists hakrawler; then
        echo -e "${GREEN}[✓] hakrawler installed${NC}"
    else
        echo -e "${RED}[✗] hakrawler installation failed${NC}"
    fi
else
    echo -e "${GREEN}[5/8] hakrawler already installed${NC}"
fi

# gf - A wrapper around grep for pattern matching
if ! command_exists gf; then
    echo -e "${YELLOW}[6/8] Installing gf...${NC}"
    go install github.com/tomnomnom/gf@latest >/dev/null 2>&1

    # Install gf patterns
    if [[ ! -d ~/.gf ]]; then
        echo -e "${YELLOW}  [*] Installing gf patterns...${NC}"
        mkdir -p ~/.gf
        git clone -q https://github.com/1ndianl33t/Gf-Patterns ~/.gf-patterns 2>/dev/null
        git clone -q https://github.com/dwisiswant0/gf-secrets ~/.gf-secrets 2>/dev/null
        cp ~/.gf-patterns/*.json ~/.gf/ 2>/dev/null
        cp ~/.gf-secrets/*.json ~/.gf/ 2>/dev/null

        # Create custom redirect pattern if not exists
        cat > ~/.gf/redirect.json << 'GFEOF'
{
    "flags": "-iE",
    "patterns": [
        "url=",
        "redirect=",
        "redir=",
        "return=",
        "next=",
        "destination=",
        "dest=",
        "continue=",
        "view=",
        "target=",
        "to=",
        "out=",
        "link=",
        "site=",
        "location=",
        "domain=",
        "reference=",
        "ref=",
        "path=",
        "window=",
        "uri=",
        "forward=",
        "forwardurl=",
        "goto=",
        "go=",
        "ReturnUrl=",
        "redirect_url=",
        "redirect_uri=",
        "redirectUrl=",
        "redirectUri=",
        "return_url=",
        "returnUrl=",
        "next_url=",
        "nextUrl=",
        "callback=",
        "callback_url=",
        "callbackUrl=",
        "continue_url=",
        "continueUrl="
    ]
}
GFEOF
        echo -e "${GREEN}  [✓] gf patterns installed${NC}"
    fi

    if command_exists gf; then
        echo -e "${GREEN}[✓] gf installed${NC}"
    else
        echo -e "${RED}[✗] gf installation failed${NC}"
    fi
else
    echo -e "${GREEN}[6/8] gf already installed${NC}"
fi

# qsreplace - Query string replacer
if ! command_exists qsreplace; then
    echo -e "${YELLOW}[7/8] Installing qsreplace...${NC}"
    go install github.com/tomnomnom/qsreplace@latest >/dev/null 2>&1
    if command_exists qsreplace; then
        echo -e "${GREEN}[✓] qsreplace installed${NC}"
    else
        echo -e "${RED}[✗] qsreplace installation failed${NC}"
    fi
else
    echo -e "${GREEN}[7/8] qsreplace already installed${NC}"
fi

# unfurl - URL extraction tool
if ! command_exists unfurl; then
    echo -e "${YELLOW}[8/8] Installing unfurl...${NC}"
    go install github.com/tomnomnom/unfurl@latest >/dev/null 2>&1
    if command_exists unfurl; then
        echo -e "${GREEN}[✓] unfurl installed${NC}"
    else
        echo -e "${RED}[✗] unfurl installation failed${NC}"
    fi
else
    echo -e "${GREEN}[8/8] unfurl already installed${NC}"
fi

echo ""
echo -e "${BLUE}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Installation completed!${NC}"
echo -e "${BLUE}══════════════════════════════════════════════${NC}"
echo ""

# Check which tools are installed
echo -e "${BLUE}[*] Verifying installed tools:${NC}"
echo ""

TOOLS=("httpx" "waybackurls" "gau" "katana" "hakrawler" "gf" "qsreplace" "unfurl" "python3")
INSTALLED=0
TOTAL=${#TOOLS[@]}

for tool in "${TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}  [✓] $tool${NC}"
        ((INSTALLED++))
    else
        echo -e "${RED}  [✗] $tool${NC}"
    fi
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}Installed: $INSTALLED/$TOTAL tools${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo ""

if [[ $INSTALLED -eq $TOTAL ]]; then
    echo -e "${GREEN}[✓] All tools installed successfully!${NC}"
else
    echo -e "${YELLOW}[!] Some tools failed to install. You may need to install them manually.${NC}"
fi

echo ""
echo -e "${YELLOW}[!] IMPORTANT: Run 'source ~/.bashrc' or restart your terminal to update PATH${NC}"
echo -e "${YELLOW}[!] Then verify by running: httpx -version${NC}"
echo ""
echo -e "${GREEN}[*] You can now use ./open-redirect-scanner.sh${NC}"
