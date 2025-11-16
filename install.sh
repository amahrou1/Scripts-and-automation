#!/bin/bash

# Installation script for Open Redirect Scanner

echo "==================================="
echo "Open Redirect Scanner - Quick Setup"
echo "==================================="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "[*] Go is not installed. Installing..."

    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        cd /tmp
        wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

        # Add to PATH
        if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        fi

        export PATH=$PATH:/usr/local/go/bin
        echo "[✓] Go installed successfully"
    else
        echo "[!] Please install Go manually from https://golang.org/dl/"
        exit 1
    fi
else
    echo "[✓] Go is already installed"
fi

# Display Go version
GO_VERSION=$(go version)
echo "[*] $GO_VERSION"
echo ""

# Build the binary
echo "[*] Building scanner..."
go build -o openredirect main.go

if [ $? -eq 0 ]; then
    chmod +x openredirect
    echo "[✓] Build successful!"
    echo ""
    echo "==================================="
    echo "Installation Complete!"
    echo "==================================="
    echo ""
    echo "Quick Start:"
    echo "  1. Create URLs file: cp urls.example.txt urls.txt"
    echo "  2. Edit urls.txt with your target URLs"
    echo "  3. Run scanner: ./openredirect -l urls.txt -t 500"
    echo ""
    echo "Full Options:"
    echo "  ./openredirect -l urls.txt -o results -t 500 -w <discord_webhook>"
    echo ""
    echo "For help:"
    echo "  ./openredirect -h"
    echo ""
else
    echo "[✗] Build failed"
    exit 1
fi
