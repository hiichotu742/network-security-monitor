document.addEventListener("DOMContentLoaded", function () {
    // 📊 Chart Monitoring Logic
    const ctxCpu = document.getElementById('cpuChart').getContext('2d');
    const ctxMemory = document.getElementById('memoryChart').getContext('2d');
    const ctxNetwork = document.getElementById('networkChart').getContext('2d');

    const cpuChart = new Chart(ctxCpu, { type: 'line', data: { labels: [], datasets: [{ label: 'CPU Usage (%)', data: [], borderColor: 'red' }] }, options: { responsive: true } });
    const memoryChart = new Chart(ctxMemory, { type: 'line', data: { labels: [], datasets: [{ label: 'Memory Usage (%)', data: [], borderColor: 'blue' }] }, options: { responsive: true } });
    const networkChart = new Chart(ctxNetwork, { type: 'line', data: { labels: [], datasets: [{ label: 'Network Traffic (bytes)', data: [], borderColor: 'green' }] }, options: { responsive: true } });

    function updateCharts() {
        fetch("/stats")
            .then(response => response.json())
            .then(data => {
                const time = new Date().toLocaleTimeString();
                [cpuChart, memoryChart, networkChart].forEach(chart => {
                    if (chart.data.labels.length > 20) {
                        chart.data.labels.shift();
                        chart.data.datasets[0].data.shift();
                    }
                });

                cpuChart.data.labels.push(time);
                cpuChart.data.datasets[0].data.push(data.cpu_usage);
                cpuChart.update();

                memoryChart.data.labels.push(time);
                memoryChart.data.datasets[0].data.push(data.memory_usage);
                memoryChart.update();

                networkChart.data.labels.push(time);
                networkChart.data.datasets[0].data.push(data.network_io);
                networkChart.update();
            });
    }

    setInterval(updateCharts, 500);
    updateCharts();

    // 💬 Chatbot Toggle & Attack Log Fetching
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
