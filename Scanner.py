#!/usr/bin/python3

import nmap

# Dictionary mapping scan options to nmap command line arguments
resp_dict = {
    '1': ['-v -sS -Pn -F', 'tcp'], # SYN ACK Scan with Fast Scan option
    '2': ['-v -sU -Pn -F', 'udp'], # UDP Scan with Fast Scan option
    '3': ['-v -sS -sV -sC -A -O -Pn -F', 'tcp'] # Comprehensive Scan with Fast Scan option
}

def create_scanner():
    """
    Creates and returns an Nmap PortScanner object.
    """
    return nmap.PortScanner()

def get_ip_address():
    """
    Prompts the user to enter an IP address for scanning and returns it.
    """
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    return ip_addr

def get_scan_type():
    """
    Prompts the user to choose a type of scan and returns the user's choice.
    """
    resp = input("""\nPlease enter the type of scan you want to run
                    1) SYN ACK Scan
                    2) UDP Scan
                    3) Comprehensive Scan \n""")
    print("You have selected option: ", resp)
    return resp

def perform_scan(scanner, ip_addr, scan_type):
    """
    Performs the scan based on the user's chosen scan type on the specified IP address.
    Returns the scanner object after the scan.
    """
    if scan_type not in resp_dict:
        print("Enter a valid option")
        return None

    print("nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr, arguments=resp_dict[scan_type][0])
    print(scanner.scaninfo())
    return scanner

def display_results(scanner, ip_addr, scan_type):
    """
    Displays the results of the scan including the scanner status,
    protocols used, and any open ports found.
    """
    if 'up' in scanner[ip_addr].state():
        print("Scanner Status: ", scanner[ip_addr].state())
        print("Protocols: ", scanner[ip_addr].all_protocols())

        protocol = resp_dict[scan_type][1]
        if protocol in scanner[ip_addr].all_protocols():
            print("Open Ports: ", scanner[ip_addr][protocol].keys())
        else:
            print(f"No open ports found for {protocol} protocol.")
    else:
        print("No information for host {}. The host may be down or not reachable.".format(ip_addr))

def main():
    """
    Main function to run the Nmap automation tool.
    """
    print("Welcome, this is a simple nmap automation tool")
    print("<----------------------------------------------------->")

    scanner = create_scanner()
    ip_addr = get_ip_address()
    scan_type = get_scan_type()
    if perform_scan(scanner, ip_addr, scan_type):
        display_results(scanner, ip_addr, scan_type)

if __name__ == '__main__':
    main()
