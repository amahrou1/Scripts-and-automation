#!/bin/bash

# Build script for Open Redirect Scanner

echo "Building Open Redirect Scanner..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed"
    echo "Install Go from: https://golang.org/dl/"
    exit 1
fi

# Get Go version
GO_VERSION=$(go version)
echo "Using: $GO_VERSION"

# Build for current platform
echo "Building for current platform..."
go build -o openredirect main.go

if [ $? -eq 0 ]; then
    echo "✓ Build successful!"
    echo "Binary: ./openredirect"
    echo ""
    echo "Usage:"
    echo "  ./openredirect -l urls.txt -t 500"
    echo ""
    chmod +x openredirect
else
    echo "✗ Build failed"
    exit 1
fi

# Optional: Build for multiple platforms
read -p "Build for Linux, Mac, and Windows? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Building for multiple platforms..."

    # Linux
    echo "Building for Linux..."
    GOOS=linux GOARCH=amd64 go build -o openredirect-linux main.go

    # Mac
    echo "Building for Mac..."
    GOOS=darwin GOARCH=amd64 go build -o openredirect-mac main.go

    # Windows
    echo "Building for Windows..."
    GOOS=windows GOARCH=amd64 go build -o openredirect.exe main.go

    echo ""
    echo "✓ All builds completed!"
    echo "  - openredirect-linux (Linux)"
    echo "  - openredirect-mac (macOS)"
    echo "  - openredirect.exe (Windows)"
fi

echo ""
echo "Done!"
