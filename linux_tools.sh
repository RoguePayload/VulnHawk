#!/bin/bash

# Update the package list
sudo apt update

# Install required tools
sudo apt install -y nmap nikto zaproxy metasploit-framework python3-pip

# Install Python dependencies
pip3 install aiohttp beautifulsoup4

echo "All required tools and dependencies for VulnHawk have been installed."
