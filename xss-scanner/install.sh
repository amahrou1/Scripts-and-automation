#!/bin/bash

# XSS Scanner Installation Script

set -e

echo "=========================================="
echo "  XSS Scanner Installation"
echo "=========================================="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "[+] Go is not installed. Installing Go..."

    # Detect architecture
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        GO_ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        GO_ARCH="arm64"
    else
        echo "[-] Unsupported architecture: $ARCH"
        exit 1
    fi

    # Download and install Go
    GO_VERSION="1.21.5"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    rm "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"

    # Add Go to PATH
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin

    echo "[+] Go installed successfully"
else
    echo "[+] Go is already installed: $(go version)"
fi

echo ""
echo "[+] Building XSS scanner..."

# Build the scanner
go build -o xss-scanner main.go

# Make it executable
chmod +x xss-scanner

echo "[+] Build complete!"
echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Usage:"
echo "  ./xss-scanner -f urls.txt"
echo "  ./xss-scanner -f urls.txt -discord https://discord.com/api/webhooks/..."
echo ""
echo "Options:"
echo "  -f          File containing URLs to test (required)"
echo "  -c          Concurrency (default: 50)"
echo "  -t          Timeout in seconds (default: 10)"
echo "  -discord    Discord webhook URL"
echo ""
echo "Example URLs file format:"
echo "  https://example.com/page?id=123"
echo "  https://test.com/search?q=test"
echo ""
echo "For more information, see README.md"
echo ""
