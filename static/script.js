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
