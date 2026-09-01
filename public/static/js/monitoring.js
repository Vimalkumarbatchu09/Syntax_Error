/**
 * NetGuard AI - Network Monitoring JavaScript
 * Manages 8 real-time Chart.js telemetry instances for:
 * Bandwidth, Latency, Packet Loss, CPU, Memory, Active Connections, Packets Sent, Packets Received
 */

const charts = {};

document.addEventListener('DOMContentLoaded', () => {
  initMonitoringCharts();
  fetchMonitoringData();
  setInterval(fetchMonitoringData, 3000);
});

function initMonitoringCharts() {
  const chartConfigs = [
    { id: 'chart-bandwidth', label: 'Bandwidth (Mbps)', color: '#00f0ff', bg: 'rgba(0, 240, 255, 0.15)' },
    { id: 'chart-latency', label: 'Latency (ms)', color: '#8b5cf6', bg: 'rgba(139, 92, 246, 0.15)' },
    { id: 'chart-packet-loss', label: 'Packet Loss (%)', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
    { id: 'chart-cpu', label: 'CPU Utilization (%)', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
    { id: 'chart-memory', label: 'Memory (%)', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)' },
    { id: 'chart-connections', label: 'Active Sockets', color: '#a855f7', bg: 'rgba(168, 85, 247, 0.15)' },
    { id: 'chart-packets-sent', label: 'Packets Sent (pps)', color: '#10b981', bg: 'rgba(16, 185, 129, 0.15)' },
    { id: 'chart-packets-recv', label: 'Packets Recv (pps)', color: '#06b6d4', bg: 'rgba(6, 182, 212, 0.15)' }
  ];

  chartConfigs.forEach(cfg => {
    const canvas = document.getElementById(cfg.id);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    charts[cfg.id] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: cfg.label,
          data: [],
          borderColor: cfg.color,
          backgroundColor: cfg.bg,
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 1.5,
          pointHoverRadius: 5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0d1424',
            titleColor: cfg.color,
            bodyColor: '#fff',
            borderColor: cfg.color,
            borderWidth: 1
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9 }, maxTicksLimit: 8 }
          },
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 9 } }
          }
        }
      }
    });
  });
}

async function fetchMonitoringData() {
  try {
    const res = await fetch('/api/network-data');
    if (!res.ok) return;

    const data = await res.json();
    const history = data.history || [];
    const endpoints = data.endpoints || [];

    if (history.length === 0) return;

    const timestamps = history.map(h => h.time);

    // Update Bandwidth
    updateSingleChart('chart-bandwidth', timestamps, history.map(h => h.bandwidth));
    // Update Latency
    updateSingleChart('chart-latency', timestamps, history.map(h => h.latency));
    // Update Packet Loss
    updateSingleChart('chart-packet-loss', timestamps, history.map(h => h.packet_loss));
    // Update CPU
    updateSingleChart('chart-cpu', timestamps, history.map(h => h.cpu));

    // For memory, conns, sent, recv compute aggregate averages across current endpoints
    if (endpoints.length > 0) {
      const avgRam = roundVal(endpoints.reduce((a, b) => a + (b.memory_utilization || 0), 0) / endpoints.length);
      const totalConns = endpoints.reduce((a, b) => a + (b.active_connections || 0), 0);
      const totalSent = endpoints.reduce((a, b) => a + (b.packets_sent || 0), 0);
      const totalRecv = endpoints.reduce((a, b) => a + (b.packets_received || 0), 0);

      // Latest values for headers
      document.getElementById('mon-val-bw').textContent = `${history[history.length - 1].bandwidth} Mbps`;
      document.getElementById('mon-val-lat').textContent = `${history[history.length - 1].latency} ms`;
      document.getElementById('mon-val-loss').textContent = `${history[history.length - 1].packet_loss}%`;
      document.getElementById('mon-val-cpu').textContent = `${history[history.length - 1].cpu}%`;
      document.getElementById('mon-val-mem').textContent = `${avgRam}%`;
      document.getElementById('mon-val-conns').textContent = totalConns.toLocaleString();
      document.getElementById('mon-val-sent').textContent = `${totalSent.toLocaleString()} pps`;
      document.getElementById('mon-val-recv').textContent = `${totalRecv.toLocaleString()} pps`;

      // Update remaining charts
      appendRollingPoint('chart-memory', timestamps[timestamps.length - 1], avgRam);
      appendRollingPoint('chart-connections', timestamps[timestamps.length - 1], totalConns);
      appendRollingPoint('chart-packets-sent', timestamps[timestamps.length - 1], totalSent);
      appendRollingPoint('chart-packets-recv', timestamps[timestamps.length - 1], totalRecv);
    }

  } catch (err) {
    console.error('Error fetching telemetry monitoring:', err);
  }
}

function updateSingleChart(id, labels, data) {
  const chart = charts[id];
  if (!chart) return;
  chart.data.labels = labels;
  chart.data.datasets[0].data = data;
  chart.update('none');
}

function appendRollingPoint(id, timestamp, val) {
  const chart = charts[id];
  if (!chart) return;

  if (chart.data.labels.length >= 25) {
    chart.data.labels.shift();
    chart.data.datasets[0].data.shift();
  }

  chart.data.labels.push(timestamp);
  chart.data.datasets[0].data.push(val);
  chart.update('none');
}

function roundVal(v) {
  return Math.round(v * 10) / 10;
}
