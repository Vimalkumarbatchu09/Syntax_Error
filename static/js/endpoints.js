/**
 * NetGuard AI - Endpoints Management JavaScript
 * Handles simulated endpoint cards, status indicators, and detailed endpoint inspector modal.
 */

let epHistoryChart = null;
let currentInspectedEpId = null;

document.addEventListener('DOMContentLoaded', () => {
  loadEndpoints();
  setInterval(loadEndpoints, 3000);

  const refreshBtn = document.getElementById('btn-refresh-endpoints');
  if (refreshBtn) refreshBtn.addEventListener('click', loadEndpoints);

  initEndpointModalListeners();

  // Check URL hash (e.g. #EP-002) to open specific modal if navigated from dashboard
  if (window.location.hash) {
    const targetEp = window.location.hash.replace('#', '');
    setTimeout(() => openEndpointModal(targetEp), 400);
  }
});

async function loadEndpoints() {
  try {
    const res = await fetch('/api/endpoints');
    if (!res.ok) return;

    const data = await res.json();
    const endpoints = data.endpoints || [];
    renderEndpointCards(endpoints);
  } catch (err) {
    console.error('Failed to load endpoints:', err);
  }
}

function renderEndpointCards(endpoints) {
  const container = document.getElementById('endpoints-container');
  if (!container) return;

  container.innerHTML = '';

  endpoints.forEach(ep => {
    const card = document.createElement('div');
    card.className = 'endpoint-card';

    let badgeClass = 'badge-normal';
    let statusText = 'NORMAL';
    if (ep.status === 'Anomalous' || ep.bandwidth > 700 || ep.cpu_utilization > 80 || ep.packet_loss > 5) {
      badgeClass = 'badge-high';
      statusText = 'ANOMALOUS';
    } else if (ep.status === 'Warning' || ep.cpu_utilization > 65 || ep.latency > 50) {
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
      <div class="endpoint-role">${ep.role || 'Simulated Node'} &bull; <span style="color: var(--text-muted); font-size: 0.75rem;">${ep.location || 'Datacenter'}</span></div>
      
      <div class="endpoint-metrics-row">
        <div class="ep-metric">
          <div class="ep-metric-label">Bandwidth</div>
          <div class="ep-metric-val" style="color: var(--cyan);">${ep.bandwidth}M</div>
        </div>
        <div class="ep-metric">
          <div class="ep-metric-label">Latency</div>
          <div class="ep-metric-val" style="color: var(--purple);">${ep.latency}ms</div>
        </div>
        <div class="ep-metric">
          <div class="ep-metric-label">CPU Load</div>
          <div class="ep-metric-val" style="color: var(--amber);">${ep.cpu_utilization}%</div>
        </div>
      </div>

      <div class="endpoint-footer-stats">
        <span>RAM: <strong>${ep.memory_utilization}%</strong></span>
        <span>Conns: <strong>${ep.active_connections}</strong></span>
        <span>Anomalies: <strong style="color: ${ep.anomaly_count > 0 ? 'var(--red)' : 'var(--green)'};">${ep.anomaly_count}</strong></span>
      </div>
    `;

    card.addEventListener('click', () => openEndpointModal(ep.endpoint_id));
    container.appendChild(card);
  });
}

function initEndpointModalListeners() {
  const modal = document.getElementById('endpoint-detail-modal');
  const closeBtn = document.getElementById('ep-modal-close-btn');
  const closeFooter = document.getElementById('ep-modal-close-footer');
  const triggerSpikeBtn = document.getElementById('ep-modal-trigger-spike');

  if (closeBtn) closeBtn.addEventListener('click', closeEndpointModal);
  if (closeFooter) closeFooter.addEventListener('click', closeEndpointModal);

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeEndpointModal();
    });
  }

  if (triggerSpikeBtn) {
    triggerSpikeBtn.addEventListener('click', async () => {
      if (!currentInspectedEpId) return;
      try {
        triggerSpikeBtn.disabled = true;
        triggerSpikeBtn.textContent = 'Simulating Spike...';

        const res = await fetch('/api/generate-anomaly', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ endpoint_id: currentInspectedEpId })
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.error || `Server returned ${res.status}`);
        }

        showToast(`⚡ Injected anomaly spike into simulated node ${currentInspectedEpId}!`, 'danger');
        closeEndpointModal();
        openAnomalyModal(data.anomaly);
        loadEndpoints();
      } catch (err) {
        showToast('Error: ' + err.message, 'danger');
      } finally {
        triggerSpikeBtn.disabled = false;
        triggerSpikeBtn.textContent = '⚡ Simulate Spike on this Node';
      }
    });
  }
}

async function openEndpointModal(epId) {
  try {
    const res = await fetch(`/api/endpoints/${epId}`);
    if (!res.ok) return;

    const data = await res.json();
    currentInspectedEpId = epId;

    const modal = document.getElementById('endpoint-detail-modal');
    document.getElementById('ep-modal-title').textContent = `Endpoint Inspection: ${data.endpoint_id}`;
    document.getElementById('ep-modal-id').textContent = data.endpoint_id;
    document.getElementById('ep-modal-ip').textContent = `Simulated IP: ${data.ip_address}`;
    document.getElementById('ep-modal-role').textContent = data.role;
    document.getElementById('ep-modal-location').textContent = data.location;
    document.getElementById('ep-modal-anomaly-count').textContent = data.total_anomalies;

    const curr = data.current || {};
    document.getElementById('ep-modal-bw').textContent = `${curr.bandwidth || 0} Mbps`;
    document.getElementById('ep-modal-lat').textContent = `${curr.latency || 0} ms`;
    document.getElementById('ep-modal-loss').textContent = `${curr.packet_loss || 0} %`;
    document.getElementById('ep-modal-cpu').textContent = `${curr.cpu || curr.cpu_utilization || 0} %`;
    document.getElementById('ep-modal-ram').textContent = `${curr.memory || curr.memory_utilization || 0} %`;
    document.getElementById('ep-modal-conns').textContent = `${curr.connections || curr.active_connections || 0}`;
    document.getElementById('ep-modal-sent').textContent = `${curr.packets_sent ? curr.packets_sent.toLocaleString() : 0} pps`;
    document.getElementById('ep-modal-recv').textContent = `${curr.packets_received ? curr.packets_received.toLocaleString() : 0} pps`;

    // Filter link
    const filterLink = document.getElementById('ep-modal-filter-link');
    if (filterLink) {
      filterLink.href = `/anomalies?endpoint=${epId}`;
    }

    // Recent anomalies list
    const anomContainer = document.getElementById('ep-modal-anomalies-list');
    anomContainer.innerHTML = '';
    if (data.anomalies && data.anomalies.length > 0) {
      data.anomalies.slice(0, 4).forEach(a => {
        const row = document.createElement('div');
        row.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: rgba(0,0,0,0.3); border-radius: 6px; font-size: 0.82rem; cursor: pointer; border: 1px solid var(--border-subtle);';
        row.innerHTML = `
          <div>
            <span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span>
            <strong style="margin-left: 8px; color: #fff;">${a.anomaly_type}</strong>
            <span style="color: var(--text-muted); font-size: 0.75rem; margin-left: 6px;">(${a.timestamp})</span>
          </div>
          <span style="color: var(--cyan); font-family: var(--font-mono); font-size: 0.75rem;">Inspect &rarr;</span>
        `;
        row.onclick = () => {
          closeEndpointModal();
          openAnomalyModal(a);
        };
        anomContainer.appendChild(row);
      });
    } else {
      anomContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem; padding: 6px;">No recent anomaly events recorded on this simulated endpoint.</div>';
    }

    // Draw Mini Trend Chart
    renderEndpointHistoryChart(data.history || []);

    if (modal) modal.classList.add('active');

  } catch (err) {
    console.error('Error opening endpoint modal:', err);
  }
}

function renderEndpointHistoryChart(history) {
  const canvas = document.getElementById('endpointHistoryChart');
  if (!canvas) return;

  const labels = history.map(h => h.time);
  const bwData = history.map(h => h.bandwidth);
  const latData = history.map(h => h.latency);

  if (epHistoryChart) {
    epHistoryChart.destroy();
  }

  const ctx = canvas.getContext('2d');
  epHistoryChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Bandwidth (Mbps)',
          data: bwData,
          borderColor: '#00f0ff',
          borderWidth: 2,
          tension: 0.3,
          pointRadius: 1
        },
        {
          label: 'Latency (ms)',
          data: latData,
          borderColor: '#8b5cf6',
          borderWidth: 2,
          tension: 0.3,
          pointRadius: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#94a3b8', font: { family: 'Outfit', size: 11 } } }
      },
      scales: {
        x: { ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9 }, maxTicksLimit: 6 }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
      }
    }
  });
}

function closeEndpointModal() {
  const modal = document.getElementById('endpoint-detail-modal');
  if (modal) modal.classList.remove('active');
}
