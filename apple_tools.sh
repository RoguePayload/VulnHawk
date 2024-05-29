#!/bin/bash

# Install Homebrew if not installed
if ! command -v brew &> /dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install required tools
brew install nmap nikto zaproxy metasploit-framework python3

# Install Python dependencies
pip3 install aiohttp beautifulsoup4

echo "All required tools and dependencies for VulnHawk have been installed."
