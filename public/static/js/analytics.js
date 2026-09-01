/**
 * NetGuard AI - Analytics JavaScript
 * Renders statistical metrics, Chart.js severity doughnut chart,
 * anomaly profile horizontal bar chart, and endpoint threat distribution table.
 */

let sevChart = null;
let typesChart = null;

document.addEventListener('DOMContentLoaded', () => {
  loadAnalytics();

  window.addEventListener('netguard:anomaly-generated', () => loadAnalytics());
  window.addEventListener('netguard:anomaly-updated', () => loadAnalytics());
});

async function loadAnalytics() {
  try {
    const res = await fetch('/api/analytics');
    if (!res.ok) return;

    const data = await res.json();

    // 1. Summary cards
    document.getElementById('stat-total-traffic').textContent = `${data.total_traffic_gb || 12.4} GB`;
    document.getElementById('stat-avg-bw').textContent = `${data.avg_bandwidth || 0} Mbps`;
    document.getElementById('stat-avg-lat').textContent = `${data.avg_latency || 0} ms`;
    document.getElementById('stat-avg-loss').textContent = `${data.avg_loss || 0} %`;
    document.getElementById('stat-top-ep').textContent = data.most_affected_endpoint || 'None';

    // 2. Severity Doughnut Chart
    renderSeverityChart(data.severity_distribution || {});

    // 3. Types Bar Chart
    renderTypesChart(data.anomaly_types || {});

    // 4. Endpoint impact table
    renderEndpointImpactTable(data.endpoint_impact || []);

  } catch (err) {
    console.error('Failed to load analytics:', err);
  }
}

function renderSeverityChart(dist) {
  const canvas = document.getElementById('chart-severity-dist');
  if (!canvas) return;

  const labels = ['Low', 'Medium', 'High', 'Critical'];
  const values = [
    dist['Low'] || 0,
    dist['Medium'] || 0,
    dist['High'] || 0,
    dist['Critical'] || 0
  ];

  if (sevChart) {
    sevChart.destroy();
  }

  const ctx = canvas.getContext('2d');
  sevChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: [
          'rgba(16, 185, 129, 0.75)',  // Low
          'rgba(245, 158, 11, 0.75)',  // Medium
          'rgba(239, 68, 68, 0.75)',   // High
          'rgba(255, 26, 83, 0.85)'    // Critical
        ],
        borderColor: '#0d1424',
        borderWidth: 3,
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#f1f5f9', font: { family: 'Outfit', size: 12 }, padding: 16 }
        },
        tooltip: {
          backgroundColor: '#0d1424',
          titleColor: '#00f0ff',
          bodyColor: '#fff',
          borderColor: 'rgba(0, 240, 255, 0.3)',
          borderWidth: 1
        }
      },
      cutout: '68%'
    }
  });
}

function renderTypesChart(typeDist) {
  const canvas = document.getElementById('chart-types-dist');
  if (!canvas) return;

  const labels = Object.keys(typeDist);
  const values = Object.values(typeDist);

  if (typesChart) {
    typesChart.destroy();
  }

  const ctx = canvas.getContext('2d');
  typesChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.length ? labels : ['No Data'],
      datasets: [{
        label: 'Incident Count',
        data: values.length ? values : [0],
        backgroundColor: 'rgba(0, 240, 255, 0.65)',
        borderColor: '#00f0ff',
        borderWidth: 1.5,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1424',
          titleColor: '#00f0ff',
          bodyColor: '#fff',
          borderColor: '#00f0ff',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 1 }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#f1f5f9', font: { family: 'Outfit', size: 11 } }
        }
      }
    }
  });
}

function renderEndpointImpactTable(impactList) {
  const tbody = document.getElementById('endpoint-impact-tbody');
  if (!tbody) return;

  const ipMap = {
    'EP-001': { ip: '192.168.1.101', role: 'Core Gateway & DNS' },
    'EP-002': { ip: '192.168.1.102', role: 'App Services Cluster' },
    'EP-003': { ip: '192.168.1.103', role: 'Database Replica Node' },
    'EP-004': { ip: '192.168.1.104', role: 'Edge Proxy / API Ingress' },
    'EP-005': { ip: '192.168.1.105', role: 'Internal Storage Node' }
  };

  tbody.innerHTML = '';

  if (impactList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No endpoint anomalies recorded.</td></tr>`;
    return;
  }

  impactList.forEach(item => {
    const epId = item.endpoint_id;
    const meta = ipMap[epId] || { ip: '192.168.1.xxx', role: 'Simulated Node' };
    const cnt = item.count;

    let riskBadge = 'badge-normal';
    let riskText = 'LOW RISK';
    if (cnt >= 4) {
      riskBadge = 'badge-critical';
      riskText = 'HIGH VULNERABILITY';
    } else if (cnt >= 2) {
      riskBadge = 'badge-warning';
      riskText = 'MODERATE EXPOSURE';
    }

    const tr = document.createElement('tr');
    tr.className = 'clickable-row';
    tr.innerHTML = `
      <td class="mono" style="font-weight: 700; color: #fff;">${epId}</td>
      <td class="mono" style="color: var(--cyan);">${meta.ip}</td>
      <td>${meta.role}</td>
      <td class="mono" style="font-weight: 700; color: var(--amber);">${cnt} events</td>
      <td><span class="badge ${riskBadge}">${riskText}</span></td>
    `;
    tr.onclick = () => {
      window.location.href = `/endpoints#${epId}`;
    };
    tbody.appendChild(tr);
  });
}
