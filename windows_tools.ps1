# PowerShell script to install required tools and dependencies

# Check if Chocolatey is installed
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install required tools
choco install -y nmap nikto zaproxy metasploit python3

# Install Python dependencies
pip3 install aiohttp beautifulsoup4

Write-Output "All required tools and dependencies for VulnHawk have been installed."
