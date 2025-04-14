"""
Packet Sniffer Module
Uses Scapy to capture and analyze network packets
"""

import logging
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime

logger = logging.getLogger(__name__)

def packet_to_dict(packet):
    """
    Convert a Scapy packet to a dictionary representation
    
    Args:
        packet: Scapy packet object
    
    Returns:
        dict: Dictionary representation of the packet
    """
    packet_dict = {
        'timestamp': datetime.now().isoformat(),
        'summary': packet.summary(),
        'layers': {}
    }
    
    # IP Layer
    if IP in packet:
        packet_dict['layers']['ip'] = {
            'source': packet[IP].src,
            'destination': packet[IP].dst,
            'protocol': packet[IP].proto,
            'ttl': packet[IP].ttl,
            'length': packet[IP].len
        }
    
    # TCP Layer
    if TCP in packet:
        packet_dict['layers']['tcp'] = {
            'source_port': packet[TCP].sport,
            'destination_port': packet[TCP].dport,
            'flags': {
                'S': 1 if packet[TCP].flags & 0x02 else 0,  # SYN
                'A': 1 if packet[TCP].flags & 0x10 else 0,  # ACK
                'F': 1 if packet[TCP].flags & 0x01 else 0,  # FIN
                'R': 1 if packet[TCP].flags & 0x04 else 0,  # RST
                'P': 1 if packet[TCP].flags & 0x08 else 0,  # PSH
                'U': 1 if packet[TCP].flags & 0x20 else 0   # URG
            },
            'seq': packet[TCP].seq,
            'ack': packet[TCP].ack
        }
    
    # UDP Layer
    if UDP in packet:
        packet_dict['layers']['udp'] = {
            'source_port': packet[UDP].sport,
            'destination_port': packet[UDP].dport,
            'length': packet[UDP].len
        }
    
    # ICMP Layer
    if ICMP in packet:
        packet_dict['layers']['icmp'] = {
            'type': packet[ICMP].type,
            'code': packet[ICMP].code
        }
    
    # Add payload summary if exists - without revealing actual content
    # This is to maintain privacy of sensitive content
    if hasattr(packet, 'payload') and str(packet.payload):
        payload_len = len(str(packet.payload))
        packet_dict['payload_size'] = payload_len
        packet_dict['has_payload'] = payload_len > 0
    
    return packet_dict

def sniff_packets(interface, duration=10, filters=''):
    """
    Sniff packets on a network interface for a specified duration
    
    Args:
        interface (str): Network interface to sniff
        duration (int): Duration in seconds to sniff
        filters (str): BPF filter syntax
    
    Returns:
        dict: Captured packet data
    """
    try:
        logger.info(f"Starting packet capture on {interface} for {duration} seconds with filter: {filters}")
        
        packets = []
        start_time = time.time()
        
        def packet_callback(packet):
            # Convert packet to dictionary and add to list
            packet_data = packet_to_dict(packet)
            packets.append(packet_data)
            
            # Stop if we've reached the duration limit
            if time.time() - start_time >= duration:
                return True
        
        # Perform the packet capture
        sniff(iface=interface, prn=packet_callback, filter=filters, 
              store=0, timeout=duration, stop_filter=lambda p: time.time() - start_time >= duration)
        
        # Calculate some statistics
        total_packets = len(packets)
        protocol_count = {
            'tcp': sum(1 for p in packets if 'tcp' in p.get('layers', {})),
            'udp': sum(1 for p in packets if 'udp' in p.get('layers', {})),
            'icmp': sum(1 for p in packets if 'icmp' in p.get('layers', {})),
            'other': sum(1 for p in packets if not any(proto in p.get('layers', {}) 
                                                     for proto in ['tcp', 'udp', 'icmp']))
        }
        
        # Prepare results
        results = {
            'interface': interface,
            'duration': round(time.time() - start_time, 2),
            'total_packets': total_packets,
            'filters_applied': filters,
            'protocol_summary': protocol_count,
            'captured_at': datetime.now().isoformat(),
            'packets': packets[:1000]  # Limit to prevent overwhelming response
        }
        
        if total_packets > 1000:
            results['truncated'] = True
            results['total_captured'] = total_packets
        
        return results
        
    except Exception as e:
        logger.error(f"Error during packet sniffing: {str(e)}")
        raise Exception(f"Packet sniffing failed: {str(e)}")

if __name__ == "__main__":
    # Test the packet sniffer
    # Note: This requires admin/root privileges to run
    results = sniff_packets("eth0", 5, "tcp port 80")
    print(f"Captured {len(results['packets'])} packets") 