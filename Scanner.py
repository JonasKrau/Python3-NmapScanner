#!/usr/bin/python3

import nmap

def create_scanner():
    """
    Creates and returns an Nmap PortScanner object.
    """
    return nmap.PortScanner()

def get_ip_address():
    """
    Prompts the user to enter an IP address and returns it.
    """
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    return ip_addr

def get_scan_type():
    """
    Prompts the user to choose a type of scan and returns the user's choice.
    Available scan types are:
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan
    """
    resp = input("""\nPlease enter the type of scan you want to run
                    1)SYN ACK Scan
                    2)UDP Scan
                    3)Comprehensive Scan \n""")
    print("You have selected option: ", resp)
    return resp

def perform_scan(scanner, ip_addr, scan_type):
    """
    Performs the scan based on the user's chosen scan type on the specified IP address.
    Returns the scanner object after the scan.
    """
    resp_dict = {
        '1': ['-v -sS -Pn', 'tcp'],
        '2': ['-v -sU -Pn', 'udp'],
        '3': ['-v -sS -sV -sC -A -O -Pn', 'tcp']
    }

    if scan_type not in resp_dict.keys():
        print("Enter a valid option")
        return None

    print("nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr, "1-1024", resp_dict[scan_type][0])
    return scanner

def display_results(scanner, ip_addr, scan_type):
    """
    Displays the results of the scan including the scanner status,
    protocols used, and any open ports found.
    """
    resp_dict = {
        '1': ['-v -sS -Pn', 'tcp'],
        '2': ['-v -sU -Pn', 'udp'],
        '3': ['-v -sS -sV -sC -A -O -Pn', 'tcp']
    }

    if 'up' in scanner[ip_addr].state():
        print("\nScanner Status: ", scanner[ip_addr].state())
        print("Protocols: ", scanner[ip_addr].all_protocols())
        if resp_dict[scan_type][1] in scanner[ip_addr].all_protocols():
            print("Open Ports: ", scanner[ip_addr][resp_dict[scan_type][1]].keys())
        else:
            print("No open ports found in specified protocol.")
    else:
        print("Host seems to be down.")

def main():
    """
    Main function to run the Nmap automation tool.
    """
    print("Welcome, this is a simple nmap automation tool")
    print("<----------------------------------------------------->")

    scanner = create_scanner()
    ip_addr = get_ip_address()
    scan_type = get_scan_type()
    scanner = perform_scan(scanner, ip_addr, scan_type)

    if scanner:
        display_results(scanner, ip_addr, scan_type)

if __name__ == '__main__':
    main()
