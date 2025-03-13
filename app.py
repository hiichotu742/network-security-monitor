import logging
import os
import psutil
import threading
import time
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from network_scan import scan_network, detect_new_devices  # Import
from packet_sniffer import start_sniffing, get_alerts, get_traffic_stats  # Import
from anomaly_detector import AnomalyDetector  # Import

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename="logs/network_monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Initialize anomaly detector
anomaly_detector = AnomalyDetector()

# Global variables to store historical data
system_stats_history = []
known_devices = []
last_scan_time = None


# Get system stats
def get_system_stats():
    stats = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cpu_usage": psutil.cpu_percent(interval=0.5),
        "memory_usage": psutil.virtual_memory().percent,
        "network_sent": psutil.net_io_counters().bytes_sent,
        "network_recv": psutil.net_io_counters().bytes_recv,
        "connections": len(psutil.net_connections()),
        "disk_usage": psutil.disk_usage('/').percent
    }

    # Add to history (keep last 100 entries)
    system_stats_history.append(stats)
    if len(system_stats_history) > 100:
        system_stats_history.pop(0)

    # Check for anomalies
    is_anomaly, reason = anomaly_detector.check_system_anomaly(stats, system_stats_history)
    if is_anomaly:
        logging.warning(f"System anomaly detected: {reason}")
        get_alerts().append({
            "timestamp": stats["timestamp"],
            "type": "SYSTEM_ANOMALY",
            "message": f"System anomaly detected: {reason}",
            "severity": "WARNING"
        })

    return stats

# Background tasks
def background_tasks():
    global last_scan_time, known_devices

    while True:
        # Scan network every 5 minutes
        current_time = time.time()
        if last_scan_time is None or (current_time - last_scan_time > 300):  # 5 minutes
            logging.info("Running scheduled network scan")
            devices = scan_network()
            new_devices = detect_new_devices(devices, known_devices)

            if new_devices:
                for device in new_devices:
                    alert_msg = f"New device detected: IP {device['ip']}, MAC {device['mac']}"
                    logging.warning(alert_msg)
                    get_alerts().append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "NEW_DEVICE",
                        "message": alert_msg,
                        "severity": "WARNING"
                    })

            known_devices = devices
            last_scan_time = current_time

            # Save known devices to file
            with open("logs/known_devices.json", "w") as f:
                json.dump(known_devices, f)

        # Sleep for 30 seconds before next check
        time.sleep(30)

# Routes
@app.route("/")
def index():
    return render_template("index.html")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/stats")
def stats():
    return jsonify(get_system_stats())

@app.route("/alerts")
def alerts():
    limit = request.args.get('limit', default=20, type=int)
    return jsonify(get_alerts()[-limit:])

@app.route("/traffic")
def traffic():
    return jsonify(get_traffic_stats())

@app.route("/logs")
def get_logs():
    try:
        with open("logs/network_monitor.log", "r") as f:
            log_data = f.readlines()[-50:]  # Return last 50 log lines
        return jsonify(log_data)
    except FileNotFoundError:
        return jsonify([])

@app.route("/scan")
def scan():
    global known_devices, last_scan_time
    devices = scan_network()
    new_devices = detect_new_devices(devices, known_devices)

    if new_devices:
        for device in new_devices:
            alert_msg = f"New device detected: IP {device['ip']}, MAC {device['mac']}"
            logging.warning(alert_msg)
            get_alerts().append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "NEW_DEVICE",
                "message": alert_msg,
                "severity": "WARNING"
            })

    known_devices = devices
    last_scan_time = time.time()

    return jsonify({
        "devices": devices,
        "new_devices": new_devices
    })

@app.route("/simulate_attack")
def simulate_attack():
    attack_type = request.args.get('type', default="port_scan", type=str)

    if attack_type == "port_scan":
        message = "Simulated port scan attack detected from 192.168.1.100"
        severity = "HIGH"
    elif attack_type == "dos":
        message = "Simulated DoS attack detected - Unusual traffic volume from 10.0.0.5"
        severity = "CRITICAL"
    elif attack_type == "malware":
        message = "Simulated malware communication detected to suspicious IP 45.77.65.211"
        severity = "HIGH"
    else:
        message = f"Simulated {attack_type} attack detected"
        severity = "MEDIUM"

    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "ATTACK",
        "message": message,
        "severity": severity
    }

    get_alerts().append(alert)
    logging.warning(f"SIMULATED ATTACK: {message}")

    return jsonify({"status": "success", "alert": alert})

# Load known devices if available
try:
    with open("logs/known_devices.json", "r") as f:
        known_devices = json.load(f)
        logging.info(f"Loaded {len(known_devices)} known devices from file")
except (FileNotFoundError, json.JSONDecodeError):
    logging.info("No known devices file found, starting fresh")
    known_devices = []

# Start background threads
if __name__ == "__main__":
    # Start packet sniffing thread
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()
    logging.info("Packet sniffing started")

    # Start background tasks thread
    background_thread = threading.Thread(target=background_tasks, daemon=True)
    background_thread.start()
    logging.info("Background tasks started")

    # Start web server
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)