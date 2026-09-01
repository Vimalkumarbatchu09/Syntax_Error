/**
 * NetGuard AI - Common Global JavaScript
 * Handles live clock, navigation, toast alerts, global anomaly modal,
 * and the universal demo anomaly generator trigger.
 */

// Global state
let currentActiveAnomalyId = null;

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initMobileMenu();
  initGlobalAnomalyTrigger();
  initModalListeners();
});

// Live Clock in UTC / Local
function initClock() {
  const clockEl = document.getElementById('live-clock');
  if (!clockEl) return;

  function update() {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + ' UTC';
    clockEl.textContent = timeStr;
  }
  update();
  setInterval(update, 1000);
}

// Mobile sidebar toggle
function initMobileMenu() {
  const toggleBtn = document.getElementById('mobile-menu-toggle');
  const sidebar = document.getElementById('sidebar');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
    });
  }
}

// Universal Demo Anomaly Trigger
function initGlobalAnomalyTrigger() {
  const triggerBtn = document.getElementById('btn-global-anomaly-trigger');
  if (!triggerBtn) return;

  triggerBtn.addEventListener('click', async () => {
    try {
      triggerBtn.disabled = true;
      triggerBtn.innerHTML = `
        <svg class="spin" style="animation: spin 1s infinite linear; width: 16px; height: 16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.3"></circle>
          <path d="M12 2a10 10 0 0 1 10 10" stroke="#fff"></path>
        </svg>
        <span>Injecting...</span>
      `;

      const response = await fetch('/api/generate-anomaly', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(result.error || `Server returned ${response.status}`);
      }

      const anomaly = result.anomaly;

      // Toast alert
      showToast(
        `🚨 ${anomaly.severity.toUpperCase()} ANOMALY DETECTED on ${anomaly.endpoint_id} (${anomaly.confidence * 100}% Confidence)`,
        'danger',
        5000
      );

      // Open inspector modal directly for hackathon demonstration wow-factor
      openAnomalyModal(anomaly);

      // Broadcast custom event so dashboard or anomalies tables can refresh immediately
      window.dispatchEvent(new CustomEvent('netguard:anomaly-generated', { detail: anomaly }));

    } catch (err) {
      console.error('Failed to trigger anomaly:', err);
      showToast('Failed to simulate anomaly: ' + err.message, 'danger');
    } finally {
      triggerBtn.disabled = false;
      triggerBtn.innerHTML = `
        <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
        <span>⚡ Generate Anomaly</span>
      `;
    }
  });
}

// Modal Listeners
function initModalListeners() {
  const modal = document.getElementById('anomaly-modal');
  const closeBtn = document.getElementById('modal-close-btn');
  const closeFooterBtn = document.getElementById('modal-close-btn-footer');
  const resolveBtn = document.getElementById('modal-resolve-btn');

  if (closeBtn) closeBtn.addEventListener('click', closeAnomalyModal);
  if (closeFooterBtn) closeFooterBtn.addEventListener('click', closeAnomalyModal);

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeAnomalyModal();
    });
  }

  if (resolveBtn) {
    resolveBtn.addEventListener('click', async () => {
      if (!currentActiveAnomalyId) return;
      try {
        const res = await fetch(`/api/anomalies/${currentActiveAnomalyId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'Investigating' })
        });
        if (res.ok) {
          showToast(`Incident #${currentActiveAnomalyId} marked as Investigating.`, 'success');
          closeAnomalyModal();
          window.dispatchEvent(new CustomEvent('netguard:anomaly-updated'));
        }
      } catch (err) {
        showToast('Error updating status: ' + err.message, 'danger');
      }
    });
  }
}

// Open Anomaly Inspector Modal
function openAnomalyModal(data) {
  if (!data) return;
  currentActiveAnomalyId = data.id || null;

  const modal = document.getElementById('anomaly-modal');
  const title = document.getElementById('modal-title');
  const badge = document.getElementById('modal-severity-badge');
  const epId = document.getElementById('modal-endpoint-id');
  const ipAddr = document.getElementById('modal-ip-address');
  const confidence = document.getElementById('modal-confidence');
  const timestamp = document.getElementById('modal-timestamp');

  // Metrics
  const bw = document.getElementById('modal-bw');
  const lat = document.getElementById('modal-lat');
  const loss = document.getElementById('modal-loss');
  const cpu = document.getElementById('modal-cpu');
  const ram = document.getElementById('modal-ram');
  const conns = document.getElementById('modal-conns');
  const sent = document.getElementById('modal-sent');
  const recv = document.getElementById('modal-recv');

  // Factors, explanation, action
  const factorsList = document.getElementById('modal-factors-list');
  const explanation = document.getElementById('modal-explanation');
  const action = document.getElementById('modal-action');

  // Populate basic info
  const sev = (data.severity || 'HIGH').toUpperCase();
  title.textContent = `🚨 ${sev} Anomaly — ${data.anomaly_type || 'Abnormal Telemetry'}`;
  badge.textContent = `${sev} ANOMALY`;
  badge.className = `badge badge-${data.severity ? data.severity.toLowerCase() : 'critical'}`;

  epId.textContent = data.endpoint_id || 'EP-001';
  ipAddr.textContent = `Simulated IP: ${data.ip_address || '192.168.1.101'}`;
  
  const confVal = data.confidence ? Math.round(data.confidence * 100) : 94;
  confidence.textContent = `${confVal}% ML Confidence`;
  timestamp.textContent = `Detected: ${data.timestamp || 'Just now'}`;

  // Populate 8 Telemetry values
  bw.textContent = `${data.bandwidth || 0} Mbps`;
  lat.textContent = `${data.latency || 0} ms`;
  loss.textContent = `${data.packet_loss || 0}%`;
  cpu.textContent = `${data.cpu_utilization || 0}%`;
  ram.textContent = `${data.memory_utilization || 0}%`;
  conns.textContent = `${data.active_connections || 0}`;
  sent.textContent = `${data.packets_sent ? data.packets_sent.toLocaleString() : 0} pps`;
  recv.textContent = `${data.packets_received ? data.packets_received.toLocaleString() : 0} pps`;

  // Highlight abnormal telemetry cards
  highlightMetric(bw, (data.bandwidth || 0) > 450);
  highlightMetric(lat, (data.latency || 0) > 50);
  highlightMetric(loss, (data.packet_loss || 0) > 2.0);
  highlightMetric(cpu, (data.cpu_utilization || 0) > 65);
  highlightMetric(ram, (data.memory_utilization || 0) > 68);
  highlightMetric(conns, (data.active_connections || 0) > 180);

  // Contributing Factors List
  factorsList.innerHTML = '';
  let factors = data.contributing_factors || [];
  if (typeof factors === 'string') {
    try { factors = JSON.parse(factors); } catch (e) { factors = [factors]; }
  }

  if (factors.length === 0) {
    factorsList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No single metric exceeded strict threshold; anomaly triggered by multi-dimensional deviation.</div>';
  } else {
    factors.forEach(factorStr => {
      const item = document.createElement('div');
      item.className = 'factor-item';
      item.innerHTML = `
        <div class="factor-name">${escapeHtml(factorStr)}</div>
        <div class="factor-status">Abnormal Deviation</div>
      `;
      factorsList.appendChild(item);
    });
  }

  // Explanation & Action
  explanation.textContent = data.explanation || 'No natural-language narrative generated.';
  action.textContent = data.recommended_action || 'Monitor endpoint telemetry for recurrent variance.';

  // Show modal
  if (modal) modal.classList.add('active');
}

function highlightMetric(element, isAbnormal) {
  if (!element || !element.parentElement) return;
  if (isAbnormal) {
    element.parentElement.style.borderColor = 'rgba(239, 68, 68, 0.5)';
    element.parentElement.style.background = 'rgba(239, 68, 68, 0.12)';
    element.style.color = '#ff4d6d';
  } else {
    element.parentElement.style.borderColor = 'var(--border-subtle)';
    element.parentElement.style.background = 'rgba(0, 0, 0, 0.3)';
    element.style.color = '#fff';
  }
}

function closeAnomalyModal() {
  const modal = document.getElementById('anomaly-modal');
  if (modal) modal.classList.remove('active');
}

// Toast notification helper
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'ℹ️';
  if (type === 'danger') icon = '🚨';
  if (type === 'success') icon = '✅';

  toast.innerHTML = `
    <span>${icon}</span>
    <span style="flex: 1;">${escapeHtml(message)}</span>
    <button style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 1.1rem;" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentElement) {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }
  }, duration);
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}
