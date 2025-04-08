TISHINA - Pentesting Toolkit

TISHINA is a powerful penetration testing toolkit designed for network security research and vulnerability scanning. It includes a variety of features for network analysis, brute-force attacks, port blocking, anonymous communication, and more.
Features

    Vulnerability Scanning: Scan for open ports and vulnerabilities on a target device.

    DOS Attack: Perform Denial-of-Service (DoS) attacks on a target.

    IP Blocking/Unblocking: Block or unblock IP addresses using iptables.

    Client and Port Scanning: Analyze connected clients and check open ports.

    SSH Brute Force Attack: Perform a brute force attack on SSH using a password dictionary.

    SQL Injection Testing: Test websites for SQL injection vulnerabilities.

    Anonymous Email Sending (Via Tor): Send emails anonymously through Tor network.

    Logging: All actions are logged for security and auditing purposes.

Installation
Requirements

    Linux (Ubuntu/Debian preferred)

    Python 3.x

    iptables (for blocking/unblocking IPs and ports)

    paramiko (for SSH brute force)

    requests, aiohttp (for web requests and asynchronous functions)

    termcolor, pyfiglet (for colorful output and ASCII art)

    Tor (for anonymous email sending)

Steps to Install

    Clone the repository:

git clone https://github.com/tisheplease/tishina.git
cd tishina

Install required dependencies:

sudo apt-get update
sudo apt-get install python3-pip
sudo apt-get install tor
pip3 install -r requirements.txt

Start the program:

    sudo python3 tishina.py

    Note: You need root privileges for certain operations like blocking/unblocking IPs and scanning network ports.

Usage

    Launch the program:

    sudo python3 tishina.py

    Choose an option from the menu:

        1: Scan for vulnerabilities and open ports.

        2: Perform a DoS attack on a target.

        3: Block an IP address.

        4: Check open ports and perform SSH brute force.

        5: Unblock an IP address.

        6: View the application logs.

        7: Send an anonymous email (via Tor).

        8: Exit the program.

        9: Test a website for SQL injection vulnerabilities.

    Follow the prompts to provide necessary inputs (IP addresses, URLs, passwords, etc.).

Logging

All actions performed within the program are logged in tishina.log. This includes information about blocked/unblocked IPs, vulnerabilities found, brute force attempts, and other relevant actions. Logs help with auditing and ensuring the tool’s use is documented.
Authors

    @tisheplease (Lead Developer)
