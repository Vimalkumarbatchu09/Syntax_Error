/**
 * NetGuard AI - Anomalies History JavaScript
 * Handles filtering, table rendering, row clicks, and status updates for anomaly events.
 */

let anomaliesData = [];

document.addEventListener('DOMContentLoaded', () => {
  initUrlParams();
  loadAnomalies();

  // Filter change listeners
  document.getElementById('filter-severity').addEventListener('change', loadAnomalies);
  document.getElementById('filter-endpoint').addEventListener('change', loadAnomalies);
  document.getElementById('filter-status').addEventListener('change', loadAnomalies);
  document.getElementById('btn-refresh-anomalies').addEventListener('click', loadAnomalies);

  // Auto-refresh when an anomaly is generated or updated
  window.addEventListener('netguard:anomaly-generated', () => loadAnomalies());
  window.addEventListener('netguard:anomaly-updated', () => loadAnomalies());
});

function initUrlParams() {
  const urlParams = new URLSearchParams(window.location.search);
  const endpointParam = urlParams.get('endpoint');
  if (endpointParam) {
    const epSelect = document.getElementById('filter-endpoint');
    if (epSelect) epSelect.value = endpointParam;
  }
}

async function loadAnomalies() {
  try {
    const sev = document.getElementById('filter-severity').value;
    const ep = document.getElementById('filter-endpoint').value;
    const stat = document.getElementById('filter-status').value;

    let url = `/api/anomalies?limit=100`;
    if (sev) url += `&severity=${encodeURIComponent(sev)}`;
    if (ep) url += `&endpoint_id=${encodeURIComponent(ep)}`;
    if (stat) url += `&status=${encodeURIComponent(stat)}`;

    const res = await fetch(url);
    if (!res.ok) return;

    const data = await res.json();
    anomaliesData = data.anomalies || [];
    renderAnomaliesTable(anomaliesData);

  } catch (err) {
    console.error('Failed to load anomalies:', err);
  }
}

function renderAnomaliesTable(records) {
  const tbody = document.getElementById('anomalies-table-body');
  const countDisplay = document.getElementById('anomalies-count-display');
  if (!tbody) return;

  countDisplay.textContent = `Showing ${records.length} incident${records.length === 1 ? '' : 's'}`;

  if (records.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; padding: 36px; color: var(--text-muted);">
          No anomalous events match the selected filter criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  records.forEach(a => {
    const tr = document.createElement('tr');
    tr.className = 'clickable-row';

    const sev = (a.severity || 'HIGH').toLowerCase();
    const confVal = a.confidence ? Math.round(a.confidence * 100) : 94;

    let statusBadge = 'badge-normal';
    if (a.status === 'Active') statusBadge = 'badge-high';
    else if (a.status === 'Investigating') statusBadge = 'badge-warning';

    tr.innerHTML = `
      <td class="mono" style="color: var(--text-muted);">${escapeHtml(a.timestamp)}</td>
      <td class="mono" style="font-weight: 700; color: #fff;">${escapeHtml(a.endpoint_id)}</td>
      <td class="mono" style="color: var(--cyan);">${escapeHtml(a.ip_address)}</td>
      <td><strong>${escapeHtml(a.anomaly_type)}</strong></td>
      <td><span class="badge badge-${sev}">${escapeHtml(a.severity)}</span></td>
      <td class="mono" style="color: var(--green); font-weight: 600;">${confVal}%</td>
      <td><span class="badge ${statusBadge}">${escapeHtml(a.status || 'Active')}</span></td>
      <td>
        <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.75rem;" title="Inspect telemetry & AI narrative">
          Inspect &rarr;
        </button>
      </td>
    `;

    // Row click opens the detailed modal inspector
    tr.addEventListener('click', () => {
      openAnomalyModal(a);
    });

    tbody.appendChild(tr);
  });
}
