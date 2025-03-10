import logging
from scapy.all import ARP, Ether, srp
import socket
import ipaddress
import threading
import time

# Configure logging
logging.basicConfig(
    filename="logs/network_monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def get_local_ip():
    """Get the local IP address to determine the network range"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a public DNS server
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        return "192.168.1.1"  # Default fallback
    finally:
        s.close()

def get_network_range():
    """Determine the network range based on local IP"""
    local_ip = get_local_ip()
    try:
        # Assume a /24 network
        ip = ipaddress.IPv4Address(local_ip)
        network = ipaddress.IPv4Network(f"{ip.packed[0]}.{ip.packed[1]}.{ip.packed[2]}.0/24", strict=False)
        return str(network)
    except Exception as e:
        logging.error(f"Error determining network range: {e}")
        return "192.168.1.0/24"  # Default fallback

def scan_network(ip_range=None):
    """Scan the network for devices"""
    if ip_range is None:
        ip_range = get_network_range()
    
    logging.info(f"Scanning network: {ip_range}")
    
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        result = srp(packet, timeout=3, verbose=False)[0]
        
        devices = []
        for sent, received in result:
            device = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "last_seen": time.time()
            }
            
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
                device["hostname"] = hostname
            except socket.herror:
                device["hostname"] = "Unknown"
            
            devices.append(device)
        
        logging.info(f"Found {len(devices)} devices on the network")
        return devices
    
    except Exception as e:
        logging.error(f"Error scanning network: {e}")
        return []

def detect_new_devices(current_devices, known_devices):
    """Detect new devices on the network"""
    current_ips = {device["ip"] for device in current_devices}
    known_ips = {device["ip"] for device in known_devices}
    
    new_device_ips = current_ips - known_ips
    new_devices = [device for device in current_devices if device["ip"] in new_device_ips]
    
    if new_devices:
        logging.warning(f"Detected {len(new_devices)} new devices on the network")
    
    return new_devices

def port_scan(target_ip, ports=None):
    """Scan common ports on a specific IP"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
    
    open_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports.append({"port": port, "service": service})
        sock.close()
    
    return open_ports

# Run a test if this script is executed directly
if __name__ == "__main__":
    print("Network Scanner Testing")
    print("-----------------------")
    print(f"Local IP: {get_local_ip()}")
    print(f"Network Range: {get_network_range()}")
    
    devices = scan_network()
    print(f"\nFound {len(devices)} devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device.get('hostname', 'Unknown')}")
        
        # Test port scanning on the first device
        if devices:
            print(f"\nScanning ports on {devices[0]['ip']}:")
            open_ports = port_scan(devices[0]['ip'])
            for port in open_ports:
                print(f"Port {port['port']} ({port['service']}): Open")