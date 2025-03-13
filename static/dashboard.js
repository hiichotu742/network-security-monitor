// Chart configuration (remains the same)
const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: false,
    },
  },
  scales: {
    x: {
      grid: {
        color: "rgba(255, 255, 255, 0.1)",
      },
      ticks: {
        color: "#aaa",
      },
    },
    y: {
      beginAtZero: true,
      grid: {
        color: "rgba(255, 255, 255, 0.1)",
      },
      ticks: {
        color: "#aaa",
      },
    },
  },
  elements: {
    line: {
      tension: 0.4,
    },
  },
  animation: {
    duration: 500,
  },
};

// Initialize charts (remains the same)
const cpuChart = new Chart(
  document.getElementById("cpuChart").getContext("2d"),
  {
    type: "line",
    data: {
      labels: Array(20).fill(""), // Initialize with empty labels
      datasets: [
        {
          label: "CPU Usage %",
          data: Array(20).fill(0), // Initialize with 0 values
          borderColor: "#3498db",
          backgroundColor: "rgba(52, 152, 219, 0.2)",
          fill: true,
        },
      ],
    },
    options: chartOptions,
  }
);

const memoryChart = new Chart(
  document.getElementById("memoryChart").getContext("2d"),
  {
    type: "line",
    data: {
      labels: Array(20).fill(""),
      datasets: [
        {
          label: "Memory Usage %",
          data: Array(20).fill(0),
          borderColor: "#2ecc71",
          backgroundColor: "rgba(46, 204, 113, 0.2)",
          fill: true,
        },
      ],
    },
    options: chartOptions,
  }
);

const networkChart = new Chart(
  document.getElementById("networkChart").getContext("2d"),
  {
    type: "line",
    data: {
      labels: Array(20).fill(""),
      datasets: [
        {
          label: "Incoming (KB/s)",
          data: Array(20).fill(0),
          borderColor: "#2ecc71",
          backgroundColor: "rgba(46, 204, 113, 0.2)",
          fill: true,
        },
        {
          label: "Outgoing (KB/s)",
          data: Array(20).fill(0),
          borderColor: "#e74c3c",
          backgroundColor: "rgba(231, 76, 60, 0.2)",
          fill: true,
        },
      ],
    },
    options: {
      ...chartOptions,
      plugins: {
        legend: {
          display: true,
          position: "top",
          labels: {
            color: "#ddd",
          },
        },
      },
    },
  }
);
const protocolDistributionChart = new Chart(
  document.getElementById("protocolDistributionChart").getContext("2d"),
  {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP", "ICMP", "Other"],
      datasets: [
        {
          data: [0, 0, 0, 0], // Initialize with 0
          backgroundColor: ["#3498db", "#2ecc71", "#f39c12", "#9b59b6"],
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: "#ddd",
          },
        },
        title: {
          display: true,
          text: "Protocol Distribution",
          color: "#ddd",
        },
      },
    },
  }
);

const topTalkersChart = new Chart(
  document.getElementById("topTalkersChart").getContext("2d"),
  {
    type: "bar",
    data: {
      labels: [], // Initialize with empty labels
      datasets: [
        {
          label: "Traffic (KB)",
          data: [], // Initialize with empty data
          backgroundColor: "#3498db",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        },
        title: {
          display: true,
          text: "Top Talkers",
          color: "#ddd",
        },
      },
      scales: {
        x: {
          grid: {
            color: "rgba(255, 255, 255, 0.1)",
          },
          ticks: {
            color: "#aaa",
          },
        },
        y: {
          beginAtZero: true,
          grid: {
            color: "rgba(255, 255, 255, 0.1)",
          },
          ticks: {
            color: "#aaa",
          },
        },
      },
    },
  }
);

// Network map initialization
function initNetworkMap() {
  const networkMap = document.getElementById("networkMap");
  networkMap.innerHTML = "";

  // Add router
  addDeviceNode("router", "Router", "192.168.1.1", 200, 200);

  // Add some regular devices
  addDeviceNode("pc", "PC-1", "192.168.1.5", 100, 100);
  addDeviceNode("pc", "PC-2", "192.168.1.10", 300, 100);
  addDeviceNode("pc", "PC-3", "192.168.1.15", 100, 300);
  addDeviceNode("pc", "PC-4", "192.168.1.20", 300, 300);
}

function addDeviceNode(type, name, ip, x, y) {
  const networkMap = document.getElementById("networkMap");
  const node = document.createElement("div");
  node.className = `device-node device-${type}`;
  node.style.left = `${x}px`;
  node.style.top = `${y}px`;

  let icon;
  switch (type) {
    case "router":
      icon = "fas fa-wifi";
      break;
    case "switch":
      icon = "fas fa-exchange-alt";
      break;
    case "pc":
      icon = "fas fa-desktop";
      break;
    case "suspicious":
      icon = "fas fa-skull-crossbones";
      break;
    default:
      icon = "fas fa-question";
  }

  node.innerHTML = `<i class="${icon}"></i>`;
  node.title = `${name} (${ip})`;

  node.addEventListener("click", () => {
    alert(`Device: ${name}\nIP: ${ip}\nType: ${type}`);
  });

  networkMap.appendChild(node);
  return node;
}

// Add alerts
function addAlert(type, message, severity) {
  const alertArea = document.getElementById("alertArea");
  const alertTime = new Date().toLocaleTimeString();

  const alertItem = document.createElement("div");
  alertItem.className = `alert-item alert-${severity.toLowerCase()}`;

  let severityBadge;
  switch (severity.toLowerCase()) {
    case "critical":
      severityBadge = '<span class="badge bg-danger me-2">Critical</span>';
      break;
    case "warning":
      severityBadge =
        '<span class="badge bg-warning text-dark me-2">Warning</span>';
      break;
    default:
      severityBadge = '<span class="badge bg-info me-2">Info</span>';
  }

  alertItem.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div>
                ${severityBadge}
                <strong>${type}</strong>
            </div>
            <small class="text-muted">${alertTime}</small>
        </div>
        <div class="mt-1">${message}</div>
    `;

  alertArea.prepend(alertItem);

  // Update alert count
  const alertCount = document.getElementById("alertCount");
  alertCount.textContent = parseInt(alertCount.textContent) + 1;

  // Check if critical
  if (severity.toLowerCase() === "critical") {
    const systemStatus = document.getElementById("systemStatus");
    const statusText = document.getElementById("statusText");

    systemStatus.className = "status-indicator status-danger";
    statusText.textContent = "Critical Alert Detected";

    // Add suspicious device to map
    if (type.includes("Port Scan")) {
      addDeviceNode("suspicious", "Unknown", "192.168.1.100", 150, 150);
    }
  }

  // Add to logs
  addLogEntry(`ALERT [${severity}]: ${message}`);
}

// Add log entries
function addLogEntry(message) {
  const logArea = document.getElementById("logArea");
  const logTime = new Date().toLocaleTimeString();

  const logLine = document.createElement("p");
  logLine.className = "log-line";
  logLine.textContent = `[${logTime}] ${message}`;

  logArea.prepend(logLine);

  // Keep only the last 100 logs
  if (logArea.children.length > 100) {
    logArea.removeChild(logArea.lastChild);
  }
}
// Set up simulation button
document
  .getElementById("simulateAttackBtn")
  .addEventListener("click", function () {
    const attackType = document.getElementById("attackType").value;

    fetch(`/simulate_attack?type=${attackType}`)
      .then((response) => response.json())
      .then((data) => {
        if (data.status === "success") {
          // Get alert details from response
          const alertType = data.alert.type;
          const alertMessage = data.alert.message;
          const alertSeverity = data.alert.severity;

          // Map severity to our UI terminology
          let uiSeverity;
          switch (alertSeverity) {
            case "CRITICAL":
              uiSeverity = "Critical";
              break;
            case "HIGH":
              uiSeverity = "Critical";
              break;
            case "MEDIUM":
              uiSeverity = "Warning";
              break;
            default:
              uiSeverity = "Info";
          }

          addAlert(
            `${attackType.toUpperCase()} Attack Detected`,
            alertMessage,
            uiSeverity
          );

          // Update visuals based on attack type
          if (attackType === "dos") {
            // Spike in network traffic
            const lastData = networkChart.data.datasets[0].data;
            for (let i = 0; i < 5; i++) {
              lastData[lastData.length - 1 - i] = 2000 + Math.random() * 500;
            }
            networkChart.update();

            // Add suspicious node to network map
            addDeviceNode("suspicious", "DoS-Attacker", "10.0.0.5", 250, 250);
          } else if (attackType === "port_scan") {
            // Add suspicious node to network map
            addDeviceNode("suspicious", "Scanner", "192.168.1.100", 150, 150);
          } else if (attackType === "malware") {
            // Change a node to suspicious
            const nodes = document.querySelectorAll(".device-pc");
            if (nodes.length > 0) {
              nodes[0].className = "device-node device-suspicious";
            }
          }
        }
      })
      .catch((error) => {
        console.error("Error simulating attack:", error);
        addLogEntry(`Error simulating attack: ${error}`);
      });
  });

// Set up refresh button
document
  .getElementById("scanNetworkBtn")
  .addEventListener("click", function () {
    fetch("/scan")
      .then((response) => response.json())
      .then((data) => {
        // Clear the network map
        document.getElementById("networkMap").innerHTML = "";

        // Add each device to the map
        data.devices.forEach((device, index) => {
          // Position devices in a circular pattern
          const radius = 150;
          const angle = (index / data.devices.length) * Math.PI * 2;
          const x = 200 + radius * Math.cos(angle);
          const y = 200 + radius * Math.sin(angle);

          // Ensure device.type exists, default to 'pc' if not
          const deviceType = device.type || "pc";
          addDeviceNode(deviceType, device.name || device.ip, device.ip, x, y);
        });

        // Add log entry
        addLogEntry(
          `Network scan completed: ${data.devices.length} devices found`
        );

        // Check for new devices
        if (data.new_devices && data.new_devices.length > 0) {
          data.new_devices.forEach((device) => {
            addAlert(
              "New Device Detected",
              `New device found on network: ${device.ip} (${device.mac})`,
              "Warning"
            );
          });
        }
      })
      .catch((error) => {
        console.error("Error scanning network:", error);
        addLogEntry(`Error scanning network: ${error}`);
      });
  });

// Setup periodic data updates and initial data fetch
// Setup periodic data updates and initial data fetch
function updateData() {
  // Initialize previous network stats *inside* updateData
  let prev_net_sent = 0;
  let prev_net_recv = 0;

  // Update system stats and charts
  fetch("/stats")
    .then((response) => response.json())
    .then((data) => {
      const time = new Date().toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });

      // Update CPU chart
      cpuChart.data.labels.push(time);
      cpuChart.data.labels.shift();
      cpuChart.data.datasets[0].data.push(data.cpu_usage);
      cpuChart.data.datasets[0].data.shift();
      cpuChart.update();
      document.getElementById("cpuBadge").textContent = `${Math.round(
        data.cpu_usage
      )}%`;

      // Update Memory chart
      memoryChart.data.labels.push(time);
      memoryChart.data.labels.shift();
      memoryChart.data.datasets[0].data.push(data.memory_usage);
      memoryChart.data.datasets[0].data.shift();
      memoryChart.update();
      document.getElementById("memoryBadge").textContent = `${Math.round(
        data.memory_usage
      )}%`;

      // Calculate network rate (KB/s) - now correctly uses the *local* variables
      const net_sent_rate = prev_net_sent
        ? (data.network_sent - prev_net_sent) / 1024
        : 0;
      const net_recv_rate = prev_net_recv
        ? (data.network_recv - prev_net_recv) / 1024
        : 0;

      prev_net_sent = data.network_sent; // Update *local* prev_net_sent
      prev_net_recv = data.network_recv; // Update *local* prev_net_recv

      // Update Network chart
      networkChart.data.labels.push(time);
      networkChart.data.labels.shift();
      networkChart.data.datasets[0].data.push(net_recv_rate);
      networkChart.data.datasets[0].data.shift();
      networkChart.data.datasets[1].data.push(net_sent_rate);
      networkChart.data.datasets[1].data.shift();
      networkChart.update();

      // Update badge
      const totalTraffic = (net_sent_rate + net_recv_rate).toFixed(1);
      document.getElementById(
        "networkBadge"
      ).textContent = `${totalTraffic} KB/s`;

      // Log stats (optional)
      addLogEntry(
        `Stats - CPU: ${Math.round(data.cpu_usage)}%, Memory: ${Math.round(
          data.memory_usage
        )}%, Network: ${totalTraffic} KB/s`
      );
    })
    .catch((error) => {
      console.error("Error updating stats:", error);
      addLogEntry(`Error updating statistics: ${error}`);
    });

  // Update alerts (Corrected alert clearing logic)
  fetch("/alerts")
    .then((response) => response.json())
    .then((alerts) => {
      const alertArea = document.getElementById("alertArea");
      const displayedAlerts = alertArea.querySelectorAll(".alert-item");
      const displayedCount = displayedAlerts.length;

      // Only update if there are new alerts
      if (alerts.length > displayedCount) {
        alertArea.innerHTML = ""; // Clear only if new alerts

        alerts.forEach((alert) => {
          let severity;
          switch (alert.severity) {
            case "CRITICAL":
            case "HIGH":
              severity = "Critical";
              break;
            case "MEDIUM":
            case "WARNING":
              severity = "Warning";
              break;
            default:
              severity = "Info";
          }
          addAlert(alert.type, alert.message, severity);
        });
      }
      // Update the alert count badge
      document.getElementById("alertCount").textContent = alerts.length;
    })
    .catch((error) => {
      console.error("Error updating alerts:", error);
      addLogEntry(`Error updating alerts: ${error}`);
    });

  // Update traffic stats (Protocol Distribution and Top Talkers)
  fetch("/traffic")
    .then((response) => response.json())
    .then((trafficData) => {
      // Update Protocol Distribution Chart
      protocolDistributionChart.data.datasets[0].data = [
        trafficData.protocol_distribution.TCP || 0,
        trafficData.protocol_distribution.UDP || 0,
        trafficData.protocol_distribution.ICMP || 0,
        trafficData.protocol_distribution.Other || 0,
      ];
      protocolDistributionChart.update();

      // Update Top Talkers chart (show top 4)
      const topTalkers = Object.entries(trafficData.top_talkers)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 4);

      topTalkersChart.data.labels = topTalkers.map((entry) => entry[0]);
      topTalkersChart.data.datasets[0].data = topTalkers.map(
        (entry) => entry[1] / 1024
      ); // Convert to KB
      topTalkersChart.update();
    })
    .catch((error) => console.error("Error updating traffic stats", error));

  // Check logs (Keep only the latest 5 logs)
  fetch("/logs")
    .then((response) => response.json())
    .then((logs) => {
      if (logs && logs.length > 0) {
        const logArea = document.getElementById("logArea");
        const displayedLogs = logArea.querySelectorAll(".log-line");
        const displayedCount = displayedLogs.length;

        if (logs.length > displayedCount) {
          logs.slice(-5).forEach((log) => {
            addLogEntry(log.trim());
          });
        }
      }
    })
    .catch((error) => {
      console.error("Error updating logs:", error);
      addLogEntry(`Error updating logs: ${error}`);
    });
}

// Update data every 3 seconds
setInterval(updateData, 3000);

// Initial data update - VERY IMPORTANT TO CALL THIS ON LOAD
updateData();

// --- Simulation functions (for when backend is unavailable) ---

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function simulateCpuData() {
  const time = new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const cpuUsage = getRandomInt(10, 40);
  cpuChart.data.labels.push(time);
  cpuChart.data.labels.shift();
  cpuChart.data.datasets[0].data.push(cpuUsage);
  cpuChart.data.datasets[0].data.shift();
  cpuChart.update();
  document.getElementById("cpuBadge").textContent = `${cpuUsage}%`;
}

function simulateMemoryData() {
  const time = new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const memoryUsage = getRandomInt(30, 60);
  memoryChart.data.labels.push(time);
  memoryChart.data.labels.shift();
  memoryChart.data.datasets[0].data.push(memoryUsage);
  memoryChart.data.datasets[0].data.shift();
  memoryChart.update();
  document.getElementById("memoryBadge").textContent = `${memoryUsage}%`;
}

function simulateNetworkData() {
  const time = new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const incomingRate = getRandomInt(200, 800);
  const outgoingRate = getRandomInt(100, 500);
  networkChart.data.labels.push(time);
  networkChart.data.labels.shift();
  networkChart.data.datasets[0].data.push(incomingRate);
  networkChart.data.datasets[0].data.shift();
  networkChart.data.datasets[1].data.push(outgoingRate);
  networkChart.data.datasets[1].data.shift();
  networkChart.update();
  const totalTraffic = ((incomingRate + outgoingRate) / 1024).toFixed(1);
  document.getElementById("networkBadge").textContent = `${totalTraffic} MB/s`;
}

function startDataSimulation() {
  simulateCpuData();
  simulateMemoryData();
  simulateNetworkData();
  setInterval(simulateCpuData, 3000);
  setInterval(simulateMemoryData, 3000);
  setInterval(simulateNetworkData, 3000);
}

document.addEventListener("DOMContentLoaded", function () {
    const chatbotIcon = document.getElementById("chatbot-icon");
    const chatbotContainer = document.getElementById("chatbot-container");
    const chatbotMessages = document.getElementById("chatbot-messages");

    chatbotIcon.addEventListener("click", function () {
        if (chatbotContainer.style.display === "none" || chatbotContainer.style.display === "") {
            chatbotContainer.style.display = "block";
            fetchAttackLogs();
        } else {
            chatbotContainer.style.display = "none";
        }
    });

    async function fetchAttackLogs() {
        try {
            const response = await fetch("http://127.0.0.1:5000/get_attacks");
            const data = await response.json();

            chatbotMessages.innerHTML = ""; // Clear previous messages

            if (data.attacks.length === 0) {
                chatbotMessages.innerHTML = "<p>No recent attacks detected.</p>";
                return;
            }

            let messages = "<h4>🚨 Recent Attacks 🚨</h4>";
            data.attacks.forEach(attack => {
                messages += `<div class="attack-entry">
                                <p>⚠️ <b>${attack.attack_type}</b></p>
                                <p><i>${attack.timestamp}</i></p>
                                <p>📝 ${attack.details}</p>
                             </div>`;
            });

            chatbotMessages.innerHTML = messages;
        } catch (error) {
            chatbotMessages.innerHTML = "<p>❌ Error fetching attack data.</p>";
        }
    }
});

// Fallback
window.addEventListener("error", function (e) {
  if (e.target.tagName.toLowerCase() === "script") {
    console.warn("Script error detected, starting simulation mode");
    startDataSimulation();
  }
});

// Call initNetworkMap on DOMContentLoaded to ensure the map container exists.
document.addEventListener("DOMContentLoaded", initNetworkMap);
