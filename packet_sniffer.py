import logging
import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, conf

# Configure logging
logging.basicConfig(
    filename="logs/network_monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Global variables
_alerts = []  # Store alerts
_lock = threading.Lock()  # Thread safety lock

# Traffic statistics
_traffic_stats = {
    "total_packets": 0,
    "protocol_distribution": defaultdict(int),
    "top_talkers": defaultdict(int),
    "connections": defaultdict(int),
    "bytes_per_second": deque(maxlen=60),  # Last minute
    "packets_per_second": deque(maxlen=60),  # Last minute
    "last_update": time.time()
}

# Suspicious patterns
SUSPICIOUS_IPS = [
    "192.168.1.100",  # Example suspicious IP 
    "10.0.0.5",       # Example suspicious IP
    "45.77.65.211",   # Known malware C2 server (example)
    "89.160.20.128"   # Known phishing server (example)
]

SUSPICIOUS_PORTS = [
    4444,  # Metasploit default
    31337, # Back Orifice
    1337,  # Common backdoor
    6667,  # IRC (often used for botnet C&C)
]

# Rate limiting detection
_ip_packet_counts = defaultdict(lambda: deque(maxlen=10))  # Track last 10 seconds
_connection_attempts = defaultdict(int)  # Track connection attempts

def get_alerts():
    """Return the alerts list"""
    return _alerts

def get_traffic_stats():
    """Return the traffic statistics"""
    return _traffic_stats

def update_traffic_stats(packet, packet_size):
    """Update traffic statistics based on packet data"""
    global _traffic_stats
    
    current_time = time.time()
    _traffic_stats["total_packets"] += 1
    
    # Update protocol distribution
    if packet.haslayer(TCP):
        _traffic_stats["protocol_distribution"]["TCP"] += 1
    elif packet.haslayer(UDP):
        _traffic_stats["protocol_distribution"]["UDP"] += 1
    elif packet.haslayer(ICMP):
        _traffic_stats["protocol_distribution"]["ICMP"] += 1
    else:
        _traffic_stats["protocol_distribution"]["Other"] += 1
    
    # Update top talkers
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        _traffic_stats["top_talkers"][src_ip] += packet_size
        
        # Update connections
        connection = f"{src_ip} -> {dst_ip}"
        _traffic_stats["connections"][connection] += 1
    
    # Update bytes and packets per second
    time_diff = current_time - _traffic_stats["last_update"]
    if time_diff >= 1.0:  # One second has passed
        _traffic_stats["bytes_per_second"].append(packet_size)
        _traffic_stats["packets_per_second"].append(1)
        _traffic_stats["last_update"] = current_time
    else:
        # Update the current second
        if _traffic_stats["bytes_per_second"]:
            _traffic_stats["bytes_per_second"][-1] += packet_size
        else:
            _traffic_stats["bytes_per_second"].append(packet_size)
            
        if _traffic_stats["packets_per_second"]:
            _traffic_stats["packets_per_second"][-1] += 1
        else:
            _traffic_stats["packets_per_second"].append(1)

def check_packet_anomalies(packet):
    """Check packet for various anomalies"""
    anomalies = []
    
    if not packet.haslayer(IP):
        return anomalies
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Check for suspicious IPs
    if src_ip in SUSPICIOUS_IPS:
        anomalies.append(f"Traffic from suspicious IP: {src_ip}")
    if dst_ip in SUSPICIOUS_IPS:
        anomalies.append(f"Traffic to suspicious IP: {dst_ip}")
    
    # Check for suspicious ports
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Check for port scanning (many connections to different ports)
        connection_key = f"{src_ip}:{dst_ip}"
        with _lock:
            _connection_attempts[connection_key] += 1
            if _connection_attempts[connection_key] > 15:  # Threshold
                anomalies.append(f"Possible port scan from {src_ip} to {dst_ip}")
                _connection_attempts[connection_key] = 0  # Reset to avoid duplicate alerts
        
        if src_port in SUSPICIOUS_PORTS:
            anomalies.append(f"Connection from suspicious port: {src_port}")
        if dst_port in SUSPICIOUS_PORTS:
            anomalies.append(f"Connection to suspicious port: {dst_port}")
            
        # Check for SYN flood (many SYN packets without ACK)
        if packet[TCP].flags == 2:  # SYN flag
            with _lock:
                _ip_packet_counts[src_ip].append(time.time())
                # If we have many SYN packets in a short time period
                if len(_ip_packet_counts[src_ip]) == 10 and \
                   _ip_packet_counts[src_ip][-1] - _ip_packet_counts[src_ip][0] < 3:
                    anomalies.append(f"Possible SYN flood from {src_ip}")
    
    # Check DNS tunneling
    if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53:
        qname = packet[DNS].qd.qname.decode() if packet[DNS].qd else ""
        if len(qname) > 50:  # Suspiciously long DNS query
            anomalies.append(f"Possible DNS tunneling: {qname[:30]}...")
    
    return anomalies

def packet_sniffer(packet):
    """Process a single packet and check for anomalies"""
    # Skip packets without IP layer
    if not packet.haslayer(IP):
        return
    
    # Get packet information
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
    packet_size = len(packet)
    
    # Log basic packet info
    log_msg = f"Packet: {src_ip} → {dst_ip} ({protocol}, {packet_size} bytes)"
    logging.debug(log_msg)  # Using debug level to avoid filling logs
    
    # Update traffic statistics
    update_traffic_stats(packet, packet_size)
    
    # Check for anomalies
    anomalies = check_packet_anomalies(packet)
    
    # Log and create alerts for anomalies
    if anomalies:
        for anomaly in anomalies:
            alert_msg = f"Network anomaly detected: {anomaly}"
            logging.warning(alert_msg)
            
            with _lock:
                _alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "NETWORK_ANOMALY",
                    "message": alert_msg,
                    "severity": "WARNING",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol
                })

def start_sniffing():
    """Start sniffing packets"""
    try:
        logging.info("Starting packet sniffer...")
        # Use Layer 3 socket to avoid requiring root privileges
        conf.use_pcap = True
        sniff(prn=packet_sniffer, store=False, filter="ip", count=0)
    except Exception as e:
        logging.error(f"Error starting packet sniffer: {e}")
        # Add alert for sniffer error
        _alerts.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "SYSTEM_ERROR",
            "message": f"Failed to start packet sniffer: {str(e)}",
            "severity": "ERROR"
        })

def simulate_traffic(duration=60):
    """Simulate network traffic for demonstration purposes"""
    logging.info("Starting traffic simulation...")
    
    end_time = time.time() + duration
    while time.time() < end_time:
        # Simulate normal traffic
        packet = IP(src="192.168.1.5", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        packet_sniffer(packet)
        
        # Occasionally simulate suspicious traffic
        if time.time() % 10 < 1:  # 10% of the time
            packet = IP(src="192.168.1.100", dst="45.77.65.211") / TCP(sport=12345, dport=4444)
            packet_sniffer(packet)
        
        time.sleep(0.1)
    
    logging.info("Traffic simulation completed")

# If run directly, test with simulated traffic
if __name__ == "__main__":
    print("Starting packet sniffer test...")
    
    # Start a thread to simulate traffic
    sim_thread = threading.Thread(target=simulate_traffic, daemon=True)
    sim_thread.start()
    
    # Start the sniffer
    start_sniffing()