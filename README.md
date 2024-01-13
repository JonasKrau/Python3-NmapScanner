# Simple Nmap Automation Tool

This Python script provides a simple interface for using Nmap to perform network scans. It allows users to select from different types of scans and target specific IP addresses.

## Features

- **SYN ACK Scan:** Fast and stealthy scan for TCP ports.
- **UDP Scan:** Scans for open UDP ports.
- **Comprehensive Scan:** A detailed scan that includes service detection, operating system detection, and more.

## Customization

- The script includes a fast scan option (`-F`) by default, which scans fewer ports for quicker results.
- Users can modify the script to remove the `-F` flag and specify a custom range of ports for a more detailed scan.

## Requirements

- Python 3
- Nmap
- python-nmap library

## Installation

Ensure Nmap is installed on your system. Then, install the python-nmap library using pip:


pip install python-nmap

## Usage

Run the script with Python 3:
sudo python3 Scanner.py

Follow the on-screen prompts to enter the IP address and select the type of scan you wish to perform.

## Legal Notice

This tool is a forked version intended for educational and legal purposes only. Do not use it for any illegal activities. Users are responsible for complying with all applicable laws and regulations regarding network scanning. Unauthorized scanning and/or breaking into computer networks is illegal and may result in legal actions.

## Disclaimer

The author of this fork is not responsible for any misuse or damage caused by this tool. Please use it responsibly.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.





