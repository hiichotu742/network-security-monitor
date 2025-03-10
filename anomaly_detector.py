import logging
import numpy as np
from datetime import datetime
from collections import deque

class AnomalyDetector:
    """Detects anomalies in system and network behavior"""
    
    def __init__(self):
        """Initialize the anomaly detector"""
        self.logger = logging.getLogger("AnomalyDetector")
        
        # Window sizes for different metrics
        self.window_size = 20
        
        # Thresholds for anomaly detection
        self.thresholds = {
            "cpu_usage": 90,  # CPU usage above 90% is suspicious
            "memory_usage": 90,  # Memory usage above 90% is suspicious
            "connections_spike": 200,  # 200% increase in connections is suspicious
            "network_traffic_spike": 300,  # 300% increase in network traffic is suspicious
        }
        
        # Store the last few values to calculate changes
        self.last_values = {
            "cpu_usage": deque(maxlen=self.window_size),
            "memory_usage": deque(maxlen=self.window_size),
            "connections": deque(maxlen=self.window_size),
            "network_sent": deque(maxlen=self.window_size),
            "network_recv": deque(maxlen=self.window_size),
        }
        
    def _calculate_baseline(self, metric, data):
        """Calculate baseline statistics for a given metric"""
        values = [item[metric] for item in data if metric in item]
        if not values:
            return None, None, None
        
        # Calculate basic statistics
        mean_val = np.mean(values)
        std_val = max(np.std(values), 0.001)  # Avoid division by zero
        
        return values, mean_val, std_val
    
    def _is_outlier(self, value, mean_val, std_val, z_threshold=3.0):
        """Check if a value is an outlier based on z-score"""
        if mean_val is None or std_val is None:
            return False
        
        z_score = abs(value - mean_val) / std_val
        return z_score > z_threshold
    
    def _is_sudden_increase(self, current, history, percentage_threshold):
        """Check if there's a sudden increase in values"""
        if not history:
            return False
        
        # Calculate average of recent history
        avg_history = sum(history) / len(history)
        
        if avg_history == 0:
            return current > 0
        
        # Calculate percentage increase
        percentage_increase = ((current - avg_history) / avg_history) * 100
        
        return percentage_increase > percentage_threshold
    
    def check_system_anomaly(self, current_stats, history):
        """Check for anomalies in system statistics"""
        is_anomaly = False
        reason = ""
        
        # Update history
        for key in self.last_values:
            if key in current_stats:
                self.last_values[key].append(current_stats[key])
        
        # Check CPU usage threshold
        if current_stats["cpu_usage"] > self.thresholds["cpu_usage"]:
            is_anomaly = True
            reason = f"High CPU usage: {current_stats['cpu_usage']}%"
        
        # Check memory usage threshold
        elif current_stats["memory_usage"] > self.thresholds["memory_usage"]:
            is_anomaly = True
            reason = f"High memory usage: {current_stats['memory_usage']}%"
        
        # Check for sudden increase in connections
        elif len(self.last_values["connections"]) > 5 and self._is_sudden_increase(
            current_stats["connections"], 
            list(self.last_values["connections"])[:-1], 
            self.thresholds["connections_spike"]
        ):
            is_anomaly = True
            reason = f"Sudden increase in network connections: {current_stats['connections']}"
        
        # Check for sudden increase in network traffic
        elif len(self.last_values["network_recv"]) > 5:
            current_total = current_stats["network_sent"] + current_stats["network_recv"]
            
            # Convert deques to lists and calculate previous totals
            sent_values = list(self.last_values["network_sent"])
            recv_values = list(self.last_values["network_recv"])
            
            if len(sent_values) > 1 and len(recv_values) > 1:
                previous_sent = sum(sent_values[:-1])
                previous_recv = sum(recv_values[:-1])
                previous_total = previous_sent + previous_recv
                avg_previous = previous_total / (len(sent_values) - 1)
                
                if avg_previous > 0 and (current_total / avg_previous * 100) > self.thresholds["network_traffic_spike"]:
                    is_anomaly = True
                    reason = f"Sudden increase in network traffic"
        
        # Calculate z-scores for various metrics if we have enough history
        if len(history) > 10:
            # Check CPU usage
            cpu_values, cpu_mean, cpu_std = self._calculate_baseline("cpu_usage", history[:-1])
            if cpu_values and self._is_outlier(current_stats["cpu_usage"], cpu_mean, cpu_std):
                is_anomaly = True
                reason = f"Unusual CPU usage pattern: {current_stats['cpu_usage']}% (baseline: {cpu_mean:.1f}%)"
            
            # Check memory usage
            mem_values, mem_mean, mem_std = self._calculate_baseline("memory_usage", history[:-1])
            if mem_values and self._is_outlier(current_stats["memory_usage"], mem_mean, mem_std, z_threshold=4.0):
                is_anomaly = True
                reason = f"Unusual memory usage pattern: {current_stats['memory_usage']}% (baseline: {mem_mean:.1f}%)"
        
        return is_anomaly, reason
    
    def check_network_anomaly(self, packet_stats, history):
        """Check for anomalies in network traffic"""
        is_anomaly = False
        reason = ""
        
        # Implement network anomaly detection logic here
        # This would analyze patterns in packet data, flows, etc.
        
        return is_anomaly, reason

# Test the anomaly detector if this script is run directly
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create a detector instance
    detector = AnomalyDetector()
    
    # Generate some test data
    history = [
        {"timestamp": "2023-01-01 12:00:00", "cpu_usage": 20, "memory_usage": 40, "connections": 10, "network_sent": 1000, "network_recv": 2000},
        {"timestamp": "2023-01-01 12:01:00", "cpu_usage": 22, "memory_usage": 41, "connections": 11, "network_sent": 1100, "network_recv": 2100},
        {"timestamp": "2023-01-01 12:02:00", "cpu_usage": 25, "memory_usage": 42, "connections": 10, "network_sent": 900, "network_recv": 1900},
    ]
    
    # Test normal case
    normal_stats = {"timestamp": "2023-01-01 12:03:00", "cpu_usage": 30, "memory_usage": 45, "connections": 12, "network_sent": 1200, "network_recv": 2200}
    is_anomaly, reason = detector.check_system_anomaly(normal_stats, history)
    print(f"Normal case - Anomaly: {is_anomaly}, Reason: {reason}")
    
    # Test CPU spike
    cpu_spike_stats = {"timestamp": "2023-01-01 12:04:00", "cpu_usage": 95, "memory_usage": 45, "connections": 12, "network_sent": 1200, "network_recv": 2200}
    is_anomaly, reason = detector.check_system_anomaly(cpu_spike_stats, history)
    print(f"CPU spike - Anomaly: {is_anomaly}, Reason: {reason}")
    
    # Test connection spike
    connection_spike_stats = {"timestamp": "2023-01-01 12:05:00", "cpu_usage": 30, "memory_usage": 45, "connections": 50, "network_sent": 1200, "network_recv": 2200}
    is_anomaly, reason = detector.check_system_anomaly(connection_spike_stats, history)
    print(f"Connection spike - Anomaly: {is_anomaly}, Reason: {reason}")