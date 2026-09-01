/**
 * NetGuard AI - Dashboard JavaScript
 * Handles real-time telemetry polling (3-second interval), dynamic Chart.js
 * graphs, summary metric card updates, and clickable alert banners.
 */

let bwChart = null;
let latChart = null;
let currentLatestAlert = null;

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  fetchNetworkData();
  // Continuous 3-second live telemetry refresh
  setInterval(fetchNetworkData, 3000);

  // Listen for instant anomaly injection from the demo button
  window.addEventListener('netguard:anomaly-generated', (e) => {
    handleAnomalyInjected(e.detail);
  });
});

function initCharts() {
  const ctxBw = document.getElementById('dashboardBandwidthChart');
  const ctxLat = document.getElementById('dashboardLatencyChart');

  if (ctxBw) {
    const gradientBw = ctxBw.getContext('2d').createLinearGradient(0, 0, 0, 250);
    gradientBw.addColorStop(0, 'rgba(0, 240, 255, 0.35)');
    gradientBw.addColorStop(1, 'rgba(0, 240, 255, 0.0)');

    bwChart = new Chart(ctxBw, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'Aggregate Bandwidth (Mbps)',
          data: [],
          borderColor: '#00f0ff',
          backgroundColor: gradientBw,
          borderWidth: 2.5,
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          pointHoverRadius: 6,
          pointBackgroundColor: '#00f0ff'
        }]
      },
      options: getChartOptions('Bandwidth (Mbps)')
    });
  }

  if (ctxLat) {
    latChart = new Chart(ctxLat, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Latency (ms)',
            data: [],
            borderColor: '#8b5cf6',
            backgroundColor: 'rgba(139, 92, 246, 0.1)',
            borderWidth: 2,
            tension: 0.35,
            pointRadius: 2,
            yAxisID: 'y'
          },
          {
            label: 'Packet Loss (%)',
            data: [],
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            borderWidth: 2,
            borderDash: [4, 4],
            tension: 0.35,
            pointRadius: 2,
            yAxisID: 'y1'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            labels: { color: '#94a3b8', font: { family: 'Outfit', size: 12 } }
          },
          tooltip: {
            backgroundColor: '#0d1424',
            titleColor: '#00f0ff',
            bodyColor: '#fff',
            borderColor: 'rgba(0, 240, 255, 0.3)',
            borderWidth: 1,
            padding: 10
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
          },
          y: {
            type: 'linear',
            display: true,
            position: 'left',
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#8b5cf6', font: { family: 'JetBrains Mono', size: 10 } }
          },
          y1: {
            type: 'linear',
            display: true,
            position: 'right',
            grid: { drawOnChartArea: false },
            ticks: { color: '#f59e0b', font: { family: 'JetBrains Mono', size: 10 } }
          }
        }
      }
    });
  }
}

function getChartOptions(label) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#94a3b8', font: { family: 'Outfit', size: 12 } }
      },
      tooltip: {
        backgroundColor: '#0d1424',
        titleColor: '#00f0ff',
        bodyColor: '#fff',
        borderColor: 'rgba(0, 240, 255, 0.3)',
        borderWidth: 1,
        padding: 10
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
      }
    }
  };
}

async function fetchNetworkData() {
  try {
    const res = await fetch('/api/network-data');
    if (!res.ok) return;

    const data = await res.json();

    // 1. Update Top Summary Cards
    document.getElementById('card-total-endpoints').textContent = data.summary.total_endpoints;
    document.getElementById('card-active-endpoints').textContent = `${data.summary.active_endpoints} / ${data.summary.total_endpoints}`;
    document.getElementById('card-current-bandwidth').textContent = data.summary.current_bandwidth;
    document.getElementById('card-detected-anomalies').textContent = data.summary.detected_anomalies;
    document.getElementById('card-critical-alerts').textContent = data.summary.critical_alerts;

    // 2. Update Charts
    if (data.history && data.history.length > 0) {
      const labels = data.history.map(h => h.time);
      const bwValues = data.history.map(h => h.bandwidth);
      const latValues = data.history.map(h => h.latency);
      const lossValues = data.history.map(h => h.packet_loss);

      if (bwChart) {
        bwChart.data.labels = labels;
        bwChart.data.datasets[0].data = bwValues;
        bwChart.update('none');
      }

      if (latChart) {
        latChart.data.labels = labels;
        latChart.data.datasets[0].data = latValues;
        latChart.data.datasets[1].data = lossValues;
        latChart.update('none');
      }
    }

    // 3. Update Recent Anomaly Alert Banner
    updateAlertBanner(data.latest_alert);

    // 4. Update Simulated Endpoints Grid
    if (data.endpoints) {
      updateEndpointsGrid(data.endpoints);
    }

  } catch (err) {
    console.error('Error fetching real-time telemetry:', err);
  }
}

function updateAlertBanner(alert) {
  const box = document.getElementById('dashboard-recent-alert');
  if (!box) return;

  if (!alert) {
    box.style.display = 'none';
    return;
  }

  currentLatestAlert = alert;
  box.style.display = 'block';

  const sev = (alert.severity || 'HIGH').toUpperCase();
  document.getElementById('alert-banner-badge').textContent = `🚨 ${sev} ANOMALY — ${alert.anomaly_type || 'Abnormal Telemetry'}`;
  document.getElementById('alert-banner-time').textContent = `Detected: ${alert.timestamp || 'Recent'}`;
  document.getElementById('alert-banner-headline').textContent = 
    `Endpoint: ${alert.endpoint_id} | IP: ${alert.ip_address} | Confidence: ${Math.round(alert.confidence * 100)}%`;

  // Brief narrative
  const narrativeEl = document.getElementById('alert-banner-narrative');
  if (alert.explanation) {
    narrativeEl.textContent = alert.explanation;
  } else {
    narrativeEl.textContent = `Unusual traffic pattern detected on ${alert.endpoint_id} with significant deviation from normal telemetry.`;
  }

  document.getElementById('alert-banner-bw').textContent = `${alert.bandwidth} Mbps`;
  document.getElementById('alert-banner-conns').textContent = alert.active_connections;
  document.getElementById('alert-banner-loss').textContent = `${alert.packet_loss}%`;

  // Make banner clickable
  box.onclick = () => {
    openAnomalyModal(currentLatestAlert);
  };
}

function updateEndpointsGrid(endpoints) {
  const container = document.getElementById('dashboard-endpoints-grid');
  if (!container) return;

  container.innerHTML = '';
  endpoints.forEach(ep => {
    const card = document.createElement('div');
    card.className = 'endpoint-card';
    
    // Status badge determination
    let badgeClass = 'badge-normal';
    let statusText = 'NORMAL';
    if (ep.bandwidth > 700 || ep.cpu_utilization > 80 || ep.packet_loss > 5) {
      badgeClass = 'badge-high';
      statusText = 'ANOMALOUS';
    } else if (ep.cpu_utilization > 65 || ep.latency > 50) {
      badgeClass = 'badge-warning';
      statusText = 'WARNING';
    }

    card.innerHTML = `
      <div class="endpoint-top">
        <div class="endpoint-title-wrap">
          <span class="endpoint-id">${ep.endpoint_id}</span>
          <span class="endpoint-ip">${ep.ip_address}</span>
        </div>
        <span class="badge ${badgeClass}">${statusText}</span>
      </div>
      <div class="endpoint-role">${ep.role || 'Simulated Network Node'}</div>
      <div class="endpoint-metrics-row">
        <div class="ep-metric">
          <div class="ep-metric-label">Bandwidth</div>
          <div class="ep-metric-val">${ep.bandwidth}M</div>
        </div>
        <div class="ep-metric">
          <div class="ep-metric-label">Latency</div>
          <div class="ep-metric-val">${ep.latency}ms</div>
        </div>
        <div class="ep-metric">
          <div class="ep-metric-label">CPU</div>
          <div class="ep-metric-val">${ep.cpu_utilization}%</div>
        </div>
      </div>
      <div class="endpoint-footer-stats">
        <span>Conns: <strong>${ep.active_connections}</strong></span>
        <span>Loss: <strong>${ep.packet_loss}%</strong></span>
      </div>
    `;

    card.addEventListener('click', () => {
      // Direct navigation to endpoints detail
      window.location.href = `/endpoints#${ep.endpoint_id}`;
    });

    container.appendChild(card);
  });
}

function handleAnomalyInjected(anomaly) {
  updateAlertBanner(anomaly);
  fetchNetworkData();
}
