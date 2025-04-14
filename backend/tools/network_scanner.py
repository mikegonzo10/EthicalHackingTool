"""
Network Scanner Module
Uses nmap to scan networks for hosts and open ports
Falls back to a simpler scanner if nmap is not available
"""

import nmap
import json
import logging
import subprocess
import sys
import os
from .fallback_scanner import fallback_scan_network

logger = logging.getLogger(__name__)

def check_nmap_installed():
    """
    Check if nmap is installed and accessible in the system PATH
    
    Returns:
        bool: True if nmap is installed, False otherwise
    """
    try:
        # Try to run 'nmap -V' to check if nmap is installed
        process = subprocess.run(
            ['nmap', '-V'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return process.returncode == 0
    except FileNotFoundError:
        return False

def scan_network(target, ports=None):
    """
    Scan a network target for hosts and open ports
    
    Args:
        target (str): IP address, hostname, or network range (e.g. '192.168.1.0/24')
        ports (str): Ports to scan (e.g. '22-100' or '21,22,80,443')
    
    Returns:
        dict: Scan results with discovered hosts and ports
    """
    # Check if nmap is installed
    if not check_nmap_installed():
        logger.warning("Nmap not found. Using fallback scanner instead.")
        logger.warning("For full functionality, please install Nmap from https://nmap.org/download.html")
        
        # Use fallback scanner
        return fallback_scan_network(target, ports)
        
    try:
        scanner = nmap.PortScanner()
        
        # Configure port range
        port_range = ports if ports else '1-1024'
        
        # Arguments for nmap scan
        arguments = f'-sV -T4 -p{port_range}'
        
        logger.info(f"Starting nmap scan on {target} with args: {arguments}")
        
        # Perform scan
        scan_data = scanner.scan(hosts=target, arguments=arguments)
        
        # Process results
        results = {
            'hosts': [],
            'total_hosts': 0,
            'up_hosts': 0,
            'scan_time': scan_data.get('nmap', {}).get('scanstats', {}).get('elapsed', 'unknown')
        }
        
        # Extract host information
        for host, host_data in scan_data.get('scan', {}).items():
            if host_data.get('status', {}).get('state') == 'up':
                results['up_hosts'] += 1
                
                host_info = {
                    'ip': host,
                    'hostname': host_data.get('hostnames', [{'name': ''}])[0].get('name', ''),
                    'status': host_data.get('status', {}).get('state', ''),
                    'mac_address': host_data.get('addresses', {}).get('mac', 'Unknown'),
                    'os': host_data.get('osmatch', [{}])[0].get('name', 'Unknown') if 'osmatch' in host_data else 'Unknown',
                    'ports': []
                }
                
                # Extract port information
                for proto in host_data.get('tcp', {}):
                    port_info = host_data['tcp'][proto]
                    host_info['ports'].append({
                        'port': proto,
                        'state': port_info.get('state', ''),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('product', '') + ' ' + port_info.get('version', '')
                    })
                
                results['hosts'].append(host_info)
            
            results['total_hosts'] += 1
        
        return results
    
    except Exception as e:
        logger.error(f"Error during network scan: {str(e)}")
        raise Exception(f"Network scan failed: {str(e)}")

if __name__ == "__main__":
    # Test the scanner
    results = scan_network("127.0.0.1", "22,80,443")
    print(json.dumps(results, indent=2)) 