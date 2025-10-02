#!/usr/bin/env python3
"""
SNB PCAP Analyzer v1.0
Professional Network Traffic Analysis Tool

A comprehensive PCAP/PCAPNG analysis tool that provides detailed insights 
into network traffic with advanced security analysis, visualization, and 
reporting capabilities.

Author: SNB
Version: 1.0.0
License: MIT
Repository: https://github.com/SNB220/SNB-pcap-analyzer
"""

import scapy.all as scapy
import socket
import csv
import sys
import argparse
import ipaddress
from collections import defaultdict, Counter
import datetime
import time
try:
    import requests
    GEOLOCATION_AVAILABLE = True
except ImportError:
    GEOLOCATION_AVAILABLE = False
    print("Warning: requests not available. Geolocation features disabled.")

try:
    import matplotlib.pyplot as plt
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print("Warning: matplotlib not available. Visualization features disabled.")

# ===============================
# Version Information
# ===============================
__version__ = "1.0.0"
__author__ = "SNB"
__license__ = "MIT"
__repository__ = "https://github.com/SNB/SNB-pcap-analyzer"

# ===============================
# Get Local IP Addresses
# ===============================
def get_local_ips():
    local_ips = {}
    hostname = socket.gethostname()
    try:
        local_ips["Hostname"] = hostname
        local_ips["Resolved IPv4"] = socket.gethostbyname(hostname)

        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
                local_ips["Private IPv4 (LAN)"] = ip
            elif ip.startswith("169.254."):
                local_ips["APIPA (Fallback IPv4)"] = ip
            elif ip.startswith("fe80"):
                local_ips["IPv6 Link-Local"] = ip
            elif ":" in ip:
                local_ips["Other IPv6"] = ip
            else:
                local_ips["Other"] = ip
    except:
        pass
    return local_ips


# ===============================
# Label IP (LOCAL / LAN / PUBLIC)
# ===============================
def label_ip(ip, local_ip_values):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip in local_ip_values:
            return f"{ip} (LOCAL)"
        elif ip_obj.is_private:
            return f"{ip} (LAN)"
        else:
            return f"{ip} (PUBLIC)"
    except:
        return ip


# ===============================
# Well-known ports dictionary
# ===============================
WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIPS", 5432: "PostgreSQL"
}

# ===============================
# Get Geolocation for IP
# ===============================
def get_geolocation(ip):
    if not GEOLOCATION_AVAILABLE:
        return "N/A"
    
    try:
        # Using a free IP geolocation service with HTTPS for security
        response = requests.get(f"https://ip-api.com/json/{ip}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
        return "Unknown"
    except:
        return "Error"

# ===============================
# Analyze PCAP File (Enhanced)
# ===============================
def analyze_pcap(file):
    print("Loading and analyzing PCAP file...")
    packets = scapy.rdpcap(file)
    
    # Basic IP tracking
    source_ips = set()
    destination_ips = set()
    
    # Protocol analysis
    protocol_stats = Counter()
    
    # Traffic analysis (bytes and packets)
    traffic_by_ip = defaultdict(lambda: {'sent_packets': 0, 'received_packets': 0, 'sent_bytes': 0, 'received_bytes': 0})
    communication_pairs = defaultdict(lambda: {'packets': 0, 'bytes': 0})
    
    # Port analysis
    port_stats = Counter()
    port_by_ip = defaultdict(set)
    
    # Enhanced suspicious traffic detection
    suspicious = []
    connection_attempts = defaultdict(set)  # For port scan detection
    failed_connections = []
    dns_queries = []
    
    # Timeline analysis
    first_packet_time = None
    last_packet_time = None
    packets_over_time = []
    
    print(f"Processing {len(packets)} packets...")
    
    for i, pkt in enumerate(packets):
        # Progress indicator
        if i % 10000 == 0 and i > 0:
            print(f"Processed {i}/{len(packets)} packets...")
            
        # Timeline tracking
        if hasattr(pkt, 'time'):
            try:
                # Convert EDecimal to float for datetime compatibility
                timestamp = float(pkt.time)
                pkt_time = datetime.datetime.fromtimestamp(timestamp)
                if first_packet_time is None:
                    first_packet_time = pkt_time
                last_packet_time = pkt_time
                packets_over_time.append(pkt_time)
            except (ValueError, TypeError, OSError):
                # Skip packets with invalid timestamps
                pass
        
        # Protocol analysis
        if pkt.haslayer(scapy.IP):
            protocol_stats['IP'] += 1
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            pkt_size = len(pkt)
            
            source_ips.add(src)
            destination_ips.add(dst)
            
            # Traffic statistics
            traffic_by_ip[src]['sent_packets'] += 1
            traffic_by_ip[src]['sent_bytes'] += pkt_size
            traffic_by_ip[dst]['received_packets'] += 1
            traffic_by_ip[dst]['received_bytes'] += pkt_size
            
            # Communication pairs
            pair = tuple(sorted([src, dst]))
            communication_pairs[pair]['packets'] += 1
            communication_pairs[pair]['bytes'] += pkt_size
            
            # TCP Analysis
            if pkt.haslayer(scapy.TCP):
                protocol_stats['TCP'] += 1
                dport = pkt[scapy.TCP].dport
                sport = pkt[scapy.TCP].sport
                flags = pkt[scapy.TCP].flags
                
                port_stats[dport] += 1
                port_by_ip[src].add(dport)
                
                # Port scan detection
                connection_attempts[src].add(dport)
                
                # Failed connection detection (RST or refused)
                if flags & 0x04:  # RST flag
                    failed_connections.append((src, dst, dport, "Connection Reset"))
                
                # Suspicious ports
                if dport in [22, 23, 3389, 4444, 1234, 31337]:
                    suspicious.append((src, dst, dport, "Suspicious Port", "TCP"))
                
                # Potential backdoor ports
                if dport > 49152 or dport in range(1024, 5000):
                    if dport not in WELL_KNOWN_PORTS:
                        suspicious.append((src, dst, dport, "Unusual High Port", "TCP"))
                        
            # UDP Analysis
            elif pkt.haslayer(scapy.UDP):
                protocol_stats['UDP'] += 1
                dport = pkt[scapy.UDP].dport
                sport = pkt[scapy.UDP].sport
                
                port_stats[dport] += 1
                
                # DNS Analysis
                if dport == 53 or sport == 53:
                    if pkt.haslayer(scapy.DNS):
                        dns_layer = pkt[scapy.DNS]
                        if dns_layer.qd:  # Query
                            query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                            dns_queries.append((src, dst, query_name, "Query"))
                        if dns_layer.an:  # Answer
                            dns_queries.append((src, dst, "Response", "Answer"))
                
                # Suspicious UDP traffic
                if dport in [53, 123] and len(pkt) > 512:  # Large DNS/NTP packets
                    suspicious.append((src, dst, dport, "Possible Amplification Attack", "UDP"))
                    
            # ICMP Analysis
            elif pkt.haslayer(scapy.ICMP):
                protocol_stats['ICMP'] += 1
                icmp_type = pkt[scapy.ICMP].type
                if icmp_type == 8:  # Ping request
                    suspicious.append((src, dst, "ICMP", "Ping Sweep Potential", "ICMP"))
                    
        # ARP Analysis
        elif pkt.haslayer(scapy.ARP):
            protocol_stats['ARP'] += 1
            if pkt[scapy.ARP].op == 2:  # ARP Reply
                suspicious.append((pkt[scapy.ARP].psrc, pkt[scapy.ARP].pdst, "ARP", "ARP Spoofing Potential", "ARP"))
        
        # Other protocols
        else:
            protocol_stats['Other'] += 1
    
    # Port scan detection (more than 10 different ports from one source)
    for src_ip, ports in port_by_ip.items():
        if len(ports) > 10:
            suspicious.append((src_ip, "Multiple", "Multiple", f"Port Scan - {len(ports)} ports", "TCP"))
    
    # Failed connection analysis
    failed_by_ip = Counter()
    for src, dst, port, reason in failed_connections:
        failed_by_ip[src] += 1
    
    for ip, count in failed_by_ip.items():
        if count > 5:  # More than 5 failed connections
            suspicious.append((ip, "Multiple", "Multiple", f"Multiple Failed Connections - {count}", "TCP"))
    
    print("Analysis complete!")
    
    return {
        'source_ips': source_ips,
        'destination_ips': destination_ips,
        'protocol_stats': protocol_stats,
        'traffic_by_ip': traffic_by_ip,
        'communication_pairs': communication_pairs,
        'port_stats': port_stats,
        'suspicious': suspicious,
        'dns_queries': dns_queries,
        'timeline': {
            'first_packet': first_packet_time,
            'last_packet': last_packet_time,
            'packets_over_time': packets_over_time,
            'duration': (last_packet_time - first_packet_time) if first_packet_time and last_packet_time else None
        },
        'total_packets': len(packets)
    }


# ===============================
# Analysis Helper Functions
# ===============================
def get_top_talkers(traffic_by_ip, top_n=10):
    """Get top talkers by total traffic (packets + bytes)"""
    sorted_by_packets = sorted(traffic_by_ip.items(), 
                              key=lambda x: x[1]['sent_packets'] + x[1]['received_packets'], 
                              reverse=True)
    sorted_by_bytes = sorted(traffic_by_ip.items(), 
                            key=lambda x: x[1]['sent_bytes'] + x[1]['received_bytes'], 
                            reverse=True)
    
    return sorted_by_packets[:top_n], sorted_by_bytes[:top_n]

def get_top_ports(port_stats, top_n=10):
    """Get most accessed ports"""
    return port_stats.most_common(top_n)

def get_communication_pairs(communication_pairs, top_n=10):
    """Get most active communication pairs"""
    sorted_pairs = sorted(communication_pairs.items(), 
                         key=lambda x: x[1]['packets'], 
                         reverse=True)
    return sorted_pairs[:top_n]

def analyze_dns_patterns(dns_queries):
    """Analyze DNS queries for potential tunneling"""
    domain_stats = Counter()
    suspicious_dns = []
    
    for src, dst, query, qtype in dns_queries:
        if qtype == "Query" and query != "Response":
            domain_stats[query] += 1
            
            # Check for suspicious patterns
            if len(query) > 50:  # Very long domain names
                suspicious_dns.append((src, dst, query, "Unusually long domain name"))
            elif query.count('.') > 10:  # Too many subdomains
                suspicious_dns.append((src, dst, query, "Excessive subdomains"))
            elif any(char in query for char in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']) and len(query) > 20:
                suspicious_dns.append((src, dst, query, "Potential DNS tunneling"))
    
    return domain_stats.most_common(10), suspicious_dns

def create_visualizations(analysis_data, local_ip_values):
    """Create visualization charts"""
    if not VISUALIZATION_AVAILABLE:
        print("Matplotlib not available for visualizations")
        return
    
    try:
        # Protocol distribution pie chart
        plt.figure(figsize=(15, 12))
        
        # Plot 1: Protocol Distribution
        plt.subplot(2, 3, 1)
        protocols = list(analysis_data['protocol_stats'].keys())
        counts = list(analysis_data['protocol_stats'].values())
        plt.pie(counts, labels=protocols, autopct='%1.1f%%')
        plt.title('Protocol Distribution')
        
        # Plot 2: Top Ports
        plt.subplot(2, 3, 2)
        top_ports = get_top_ports(analysis_data['port_stats'], 10)
        if top_ports:
            ports, port_counts = zip(*top_ports)
            port_labels = [f"{port}({WELL_KNOWN_PORTS.get(port, 'Unknown')})" for port in ports]
            plt.bar(range(len(ports)), port_counts)
            plt.xticks(range(len(ports)), port_labels, rotation=45, ha='right')
            plt.title('Top 10 Destination Ports')
            plt.ylabel('Packet Count')
        
        # Plot 3: Traffic Timeline (simplified)
        plt.subplot(2, 3, 3)
        if analysis_data['timeline']['packets_over_time']:
            times = analysis_data['timeline']['packets_over_time']
            # Group packets by hour for visualization
            time_buckets = defaultdict(int)
            for t in times:
                hour_bucket = t.replace(minute=0, second=0, microsecond=0)
                time_buckets[hour_bucket] += 1
            
            if time_buckets:
                sorted_times = sorted(time_buckets.keys())
                packet_counts = [time_buckets[t] for t in sorted_times]
                plt.plot(sorted_times, packet_counts)
                plt.title('Traffic Over Time')
                plt.ylabel('Packets per Hour')
                plt.xticks(rotation=45)
        
        # Plot 4: Top Talkers by Packets
        plt.subplot(2, 3, 4)
        top_talkers_packets, _ = get_top_talkers(analysis_data['traffic_by_ip'], 10)
        if top_talkers_packets:
            ips = [label_ip(ip, local_ip_values) for ip, _ in top_talkers_packets[:5]]  # Top 5 for readability
            packet_counts = [data['sent_packets'] + data['received_packets'] for _, data in top_talkers_packets[:5]]
            plt.barh(range(len(ips)), packet_counts)
            plt.yticks(range(len(ips)), ips)
            plt.title('Top 5 Talkers by Packets')
            plt.xlabel('Total Packets')
        
        # Plot 5: Geographic Distribution (if geolocation available)
        plt.subplot(2, 3, 5)
        if GEOLOCATION_AVAILABLE:
            public_ips = [ip for ip in analysis_data['source_ips'].union(analysis_data['destination_ips'])
                         if not ipaddress.ip_address(ip).is_private and ip not in local_ip_values]
            countries = Counter()
            for ip in public_ips[:20]:  # Limit to avoid API rate limits
                location = get_geolocation(ip)
                if "," in location:
                    country = location.split(", ")[-1]
                    countries[country] += 1
            
            if countries:
                country_names = list(countries.keys())[:5]  # Top 5 countries
                country_counts = list(countries.values())[:5]
                plt.pie(country_counts, labels=country_names, autopct='%1.0f%%')
                plt.title('Top Countries (External IPs)')
        
        # Plot 6: Suspicious Activity Summary
        plt.subplot(2, 3, 6)
        if analysis_data['suspicious']:
            reasons = Counter([reason for _, _, _, reason, _ in analysis_data['suspicious']])
            reason_names = list(reasons.keys())[:5]
            reason_counts = list(reasons.values())[:5]
            plt.bar(range(len(reason_names)), reason_counts)
            plt.xticks(range(len(reason_names)), reason_names, rotation=45, ha='right')
            plt.title('Suspicious Activity Types')
            plt.ylabel('Count')
        
        plt.tight_layout()
        plt.savefig('pcap_analysis_charts.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("Charts saved as pcap_analysis_charts.png")
        
    except Exception as e:
        print(f"Error creating visualizations: {e}")

# ===============================
# Save Results to CSV (Enhanced)
# ===============================
def save_to_csv(filename, analysis_data, local_ips):
    """Save comprehensive analysis results to CSV"""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        local_ip_values = set(local_ips.values())
        
        # Analysis Summary
        writer.writerow(["=== PCAP ANALYSIS SUMMARY ==="])
        writer.writerow(["Total Packets Analyzed", analysis_data['total_packets']])
        if analysis_data['timeline']['duration']:
            writer.writerow(["Duration", str(analysis_data['timeline']['duration'])])
        writer.writerow(["First Packet", analysis_data['timeline']['first_packet']])
        writer.writerow(["Last Packet", analysis_data['timeline']['last_packet']])
        writer.writerow([])

        # Protocol Statistics
        writer.writerow(["=== PROTOCOL STATISTICS ==="])
        writer.writerow(["Protocol", "Packet Count", "Percentage"])
        total_packets = sum(analysis_data['protocol_stats'].values())
        for protocol, count in analysis_data['protocol_stats'].most_common():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            writer.writerow([protocol, count, f"{percentage:.2f}%"])
        writer.writerow([])

        # Source IPs
        writer.writerow(["=== SOURCE IPs ==="])
        writer.writerow(["IP Address", "Classification", "Location"])
        for ip in analysis_data['source_ips']:
            labeled_ip = label_ip(ip, local_ip_values)
            location = "N/A"
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and ip not in local_ip_values:
                    location = get_geolocation(ip)
            except:
                pass
            writer.writerow([labeled_ip, "Source", location])
        writer.writerow([])

        # Destination IPs
        writer.writerow(["=== DESTINATION IPs ==="])
        writer.writerow(["IP Address", "Classification", "Location"])
        for ip in analysis_data['destination_ips']:
            labeled_ip = label_ip(ip, local_ip_values)
            location = "N/A"
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and ip not in local_ip_values:
                    location = get_geolocation(ip)
            except:
                pass
            writer.writerow([labeled_ip, "Destination", location])
        writer.writerow([])

        # Top Talkers by Packets
        writer.writerow(["=== TOP TALKERS (BY PACKETS) ==="])
        writer.writerow(["IP Address", "Sent Packets", "Received Packets", "Total Packets", "Sent Bytes", "Received Bytes", "Total Bytes"])
        top_talkers_packets, top_talkers_bytes = get_top_talkers(analysis_data['traffic_by_ip'], 20)
        for ip, data in top_talkers_packets:
            labeled_ip = label_ip(ip, local_ip_values)
            writer.writerow([
                labeled_ip,
                data['sent_packets'],
                data['received_packets'],
                data['sent_packets'] + data['received_packets'],
                data['sent_bytes'],
                data['received_bytes'],
                data['sent_bytes'] + data['received_bytes']
            ])
        writer.writerow([])

        # Top Communication Pairs
        writer.writerow(["=== TOP COMMUNICATION PAIRS ==="])
        writer.writerow(["Source IP", "Destination IP", "Total Packets", "Total Bytes"])
        top_pairs = get_communication_pairs(analysis_data['communication_pairs'], 20)
        for (ip1, ip2), data in top_pairs:
            ip1_labeled = label_ip(ip1, local_ip_values)
            ip2_labeled = label_ip(ip2, local_ip_values)
            writer.writerow([ip1_labeled, ip2_labeled, data['packets'], data['bytes']])
        writer.writerow([])

        # Port Analysis
        writer.writerow(["=== TOP DESTINATION PORTS ==="])
        writer.writerow(["Port", "Service", "Packet Count"])
        top_ports = get_top_ports(analysis_data['port_stats'], 50)
        for port, count in top_ports:
            service = WELL_KNOWN_PORTS.get(port, "Unknown")
            writer.writerow([port, service, count])
        writer.writerow([])

        # DNS Analysis
        if analysis_data['dns_queries']:
            writer.writerow(["=== DNS ANALYSIS ==="])
            writer.writerow(["Source IP", "Destination IP", "Query/Response", "Type"])
            for src, dst, query, qtype in analysis_data['dns_queries'][:100]:  # Limit to first 100
                src_labeled = label_ip(src, local_ip_values)
                dst_labeled = label_ip(dst, local_ip_values)
                writer.writerow([src_labeled, dst_labeled, query, qtype])
            
            # DNS Domain Statistics
            domain_stats, suspicious_dns = analyze_dns_patterns(analysis_data['dns_queries'])
            if domain_stats:
                writer.writerow([])
                writer.writerow(["=== TOP DNS QUERIES ==="])
                writer.writerow(["Domain", "Query Count"])
                for domain, count in domain_stats:
                    writer.writerow([domain, count])
            
            if suspicious_dns:
                writer.writerow([])
                writer.writerow(["=== SUSPICIOUS DNS QUERIES ==="])
                writer.writerow(["Source IP", "Destination IP", "Domain", "Reason"])
                for src, dst, domain, reason in suspicious_dns:
                    src_labeled = label_ip(src, local_ip_values)
                    dst_labeled = label_ip(dst, local_ip_values)
                    writer.writerow([src_labeled, dst_labeled, domain, reason])
            writer.writerow([])

        # Local Machine IPs
        writer.writerow(["=== LOCAL MACHINE INFORMATION ==="])
        writer.writerow(["Type", "IP Address"])
        for label, ip in local_ips.items():
            writer.writerow([label, ip])
        writer.writerow([])

        # Suspicious Traffic (Enhanced)
        writer.writerow(["=== SUSPICIOUS TRAFFIC ANALYSIS ==="])
        if analysis_data['suspicious']:
            writer.writerow(["Source IP", "Destination IP", "Port/Protocol", "Reason", "Protocol Type"])
            for src, dst, port, reason, protocol in analysis_data['suspicious']:
                src_labeled = label_ip(src, local_ip_values)
                dst_labeled = label_ip(dst, local_ip_values) if dst != "Multiple" else dst
                writer.writerow([src_labeled, dst_labeled, port, reason, protocol])
        else:
            writer.writerow(["No suspicious traffic patterns detected"])
        
    print(f"Comprehensive analysis saved to {filename}")


# ===============================
# Main (Enhanced)
# ===============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SNB PCAP Analyzer - Professional network traffic analysis and security assessment tool"
    )
    parser.add_argument("file", nargs="?", help="Input pcap/pcapng file")
    parser.add_argument("--no-geo", action="store_true", help="Disable geolocation features")
    parser.add_argument("--no-viz", action="store_true", help="Disable visualization features")
    parser.add_argument("--output", "-o", help="Output CSV filename (default: pcap_analysis.csv)")
    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        sys.exit(1)

    # Disable features if requested (modify module-level variables)
    if args.no_geo:
        globals()['GEOLOCATION_AVAILABLE'] = False
    if args.no_viz:
        globals()['VISUALIZATION_AVAILABLE'] = False

    print("🔍 SNB PCAP Analyzer v1.0 - Professional Network Analysis Tool")
    print("=" * 65)
    
    pcap_file = args.file
    start_time = time.time()
    
    # Perform comprehensive analysis
    analysis_data = analyze_pcap(pcap_file)
    local_ips = get_local_ips()
    local_ip_values = set(local_ips.values())
    
    analysis_time = time.time() - start_time
    print(f"Analysis completed in {analysis_time:.2f} seconds")
    print("=" * 60)

    # ===== ENHANCED TERMINAL OUTPUT =====
    
    # Analysis Summary
    print("\n📊 ANALYSIS SUMMARY")
    print("-" * 40)
    print(f"Total packets analyzed: {analysis_data['total_packets']:,}")
    if analysis_data['timeline']['duration']:
        print(f"Capture duration: {analysis_data['timeline']['duration']}")
    print(f"Analysis time: {analysis_time:.2f} seconds")
    
    # Protocol Statistics
    print(f"\n🔌 PROTOCOL DISTRIBUTION")
    print("-" * 40)
    total_packets = sum(analysis_data['protocol_stats'].values())
    for protocol, count in analysis_data['protocol_stats'].most_common():
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        print(f"{protocol:>8}: {count:>8,} packets ({percentage:>5.1f}%)")

    # IP Address Analysis
    print(f"\n🌐 IP ADDRESS ANALYSIS")
    print("-" * 40)
    print(f"Unique source IPs: {len(analysis_data['source_ips'])}")
    print(f"Unique destination IPs: {len(analysis_data['destination_ips'])}")
    
    # Separate IPs by type
    all_ips = analysis_data['source_ips'].union(analysis_data['destination_ips'])
    local_count = sum(1 for ip in all_ips if ip in local_ip_values)
    private_count = sum(1 for ip in all_ips if ip not in local_ip_values and ipaddress.ip_address(ip).is_private)
    public_count = len(all_ips) - local_count - private_count
    
    print(f"Local machine IPs: {local_count}")
    print(f"Private network IPs: {private_count}")  
    print(f"Public IPs: {public_count}")

    # Top Talkers
    print(f"\n💬 TOP TALKERS")
    print("-" * 40)
    top_talkers_packets, top_talkers_bytes = get_top_talkers(analysis_data['traffic_by_ip'], 10)
    
    print("By packet count:")
    for i, (ip, data) in enumerate(top_talkers_packets[:5], 1):
        total_packets = data['sent_packets'] + data['received_packets']
        total_bytes = data['sent_bytes'] + data['received_bytes']
        print(f"{i:>2}. {label_ip(ip, local_ip_values):<25} {total_packets:>8,} packets ({total_bytes:>10,} bytes)")

    # Port Analysis
    print(f"\n🚪 PORT ANALYSIS")
    print("-" * 40)
    top_ports = get_top_ports(analysis_data['port_stats'], 10)
    for i, (port, count) in enumerate(top_ports, 1):
        service = WELL_KNOWN_PORTS.get(port, "Unknown")
        print(f"{i:>2}. Port {port:>5} ({service:<12}): {count:>6,} packets")

    # Communication Patterns
    print(f"\n🔄 TOP COMMUNICATION PAIRS")
    print("-" * 40)
    top_pairs = get_communication_pairs(analysis_data['communication_pairs'], 5)
    for i, ((ip1, ip2), data) in enumerate(top_pairs, 1):
        ip1_labeled = label_ip(ip1, local_ip_values)
        ip2_labeled = label_ip(ip2, local_ip_values)
        print(f"{i}. {ip1_labeled} ↔ {ip2_labeled}")
        print(f"   {data['packets']:,} packets, {data['bytes']:,} bytes")

    # DNS Analysis
    if analysis_data['dns_queries']:
        print(f"\n🔍 DNS ANALYSIS")
        print("-" * 40)
        domain_stats, suspicious_dns = analyze_dns_patterns(analysis_data['dns_queries'])
        print(f"Total DNS queries: {len(analysis_data['dns_queries'])}")
        
        if domain_stats:
            print("Top queried domains:")
            for i, (domain, count) in enumerate(domain_stats[:5], 1):
                print(f"{i:>2}. {domain:<30} ({count} queries)")
        
        if suspicious_dns:
            print(f"\n⚠️  Suspicious DNS patterns detected: {len(suspicious_dns)}")
            for src, dst, domain, reason in suspicious_dns[:3]:
                print(f"   {label_ip(src, local_ip_values)} → {reason}: {domain}")

    # Geographic Analysis (if available)
    if GEOLOCATION_AVAILABLE and public_count > 0:
        print(f"\n🌍 GEOGRAPHIC ANALYSIS")
        print("-" * 40)
        print("Analyzing public IP locations (this may take a moment)...")
        
        public_ips = [ip for ip in all_ips 
                     if not ipaddress.ip_address(ip).is_private and ip not in local_ip_values]
        
        locations = Counter()
        for ip in public_ips[:20]:  # Limit to avoid rate limits
            location = get_geolocation(ip)
            if location and location not in ["Unknown", "Error", "N/A"]:
                locations[location] += 1
        
        if locations:
            print("Top locations for external connections:")
            for i, (location, count) in enumerate(locations.most_common(5), 1):
                print(f"{i:>2}. {location:<25} ({count} IPs)")

    # Local Machine Information
    print(f"\n🖥️  LOCAL MACHINE INFORMATION")
    print("-" * 40)
    for label, ip in local_ips.items():
        print(f"{label:<20}: {ip}")

    # Suspicious Activity Analysis
    print(f"\n🚨 SECURITY ANALYSIS")
    print("-" * 40)
    if analysis_data['suspicious']:
        print(f"Suspicious activities detected: {len(analysis_data['suspicious'])}")
        
        # Group by reason for summary
        reasons = Counter([reason for _, _, _, reason, _ in analysis_data['suspicious']])
        for reason, count in reasons.most_common():
            print(f"  • {reason}: {count} incidents")
        
        print(f"\nTop suspicious activities:")
        for i, (src, dst, port, reason, protocol) in enumerate(analysis_data['suspicious'][:10], 1):
            src_labeled = label_ip(src, local_ip_values)
            dst_display = label_ip(dst, local_ip_values) if dst != "Multiple" else dst
            print(f"{i:>2}. {src_labeled} → {dst_display}")
            print(f"    {reason} ({protocol}, Port: {port})")
    else:
        print("✅ No obvious suspicious traffic patterns detected")

    # Timeline Information
    if analysis_data['timeline']['duration']:
        print(f"\n⏰ TIMELINE ANALYSIS")
        print("-" * 40)
        print(f"First packet: {analysis_data['timeline']['first_packet']}")
        print(f"Last packet:  {analysis_data['timeline']['last_packet']}")
        print(f"Duration:     {analysis_data['timeline']['duration']}")
        
        # Calculate packets per second
        duration_seconds = analysis_data['timeline']['duration'].total_seconds()
        if duration_seconds > 0:
            pps = analysis_data['total_packets'] / duration_seconds
            print(f"Average rate: {pps:.2f} packets per second")

    # Visualization
    if VISUALIZATION_AVAILABLE:
        create_viz = input(f"\n📊 Create visualization charts? (yes/no): ").lower()
        if create_viz == "yes":
            print("Generating visualizations...")
            create_visualizations(analysis_data, local_ip_values)

    # Save results
    print(f"\n💾 SAVE RESULTS")
    print("-" * 40)
    save = input("Save detailed analysis as CSV? (yes/no): ").lower()
    if save == "yes":
        output_file = args.output or "pcap_analysis.csv"
        save_to_csv(output_file, analysis_data, local_ips)
        print(f"✅ Detailed analysis saved to {output_file}")

    print(f"\n🎉 Analysis complete! Thank you for using SNB PCAP Analyzer v1.0!")
    print("=" * 65)
