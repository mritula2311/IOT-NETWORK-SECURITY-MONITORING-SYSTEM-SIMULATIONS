/**
 * IoT Network Security Monitor — Dashboard Logic
 * Device-aware monitoring, explainable alerts, active IPS defense, and traffic simulation
 */

// ─── Icons & Mappings ─────────────────────────────────────────────
const ROLE_ICONS = {
    gateway: '🌐',
    sensor: '🌡️',
    camera: '📷',
    server: '🖥️',
    unknown: '❓',
};

const ALERT_ICONS = {
    UNKNOWN_IP: '🚨',
    UNAUTHORIZED_SERVICE: '⛔',
    TRAFFIC_BURST: '⚡',
    PORT_SCAN_PATTERN: '🔍',
};

// ─── State ────────────────────────────────────────────────────────
let dashboardData = null;
let activeFilter = 'all';
let simInterval = null;
let simIndex = 0;
let currentScenarioEvents = [];

// ─── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    setInterval(updateClock, 1000);
    loadData();
});

function updateClock() {
    const el = document.getElementById('headerTime');
    if (el) {
        el.textContent = new Date().toLocaleTimeString('en-US', {
            hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }
}

async function loadData() {
    try {
        const resp = await fetch('data.json');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        dashboardData = await resp.json();
        renderAll();
        setStatus('Dashboard Live & Active', true);
    } catch (err) {
        console.error('Failed to load data.json:', err);
        setStatus('Data Not Found', false);
        showFallback();
    }
}

function setStatus(text, ok) {
    const badge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const dot = badge?.querySelector('.status-dot');
    if (statusText) statusText.textContent = text;
    if (dot) dot.style.background = ok ? 'var(--accent-green)' : 'var(--accent-red)';
    if (badge) {
        badge.style.borderColor = ok ? 'rgba(34, 211, 238, 0.25)' : 'rgba(248, 113, 113, 0.25)';
        badge.style.background = ok ? 'rgba(34, 211, 238, 0.1)' : 'rgba(248, 113, 113, 0.1)';
    }
}

function showFallback() {
    const el = document.getElementById('alertFeed');
    if (el) {
        el.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--text-muted);">
                <p style="font-size:2rem; margin-bottom:12px;">📊</p>
                <p style="font-weight:600; margin-bottom:8px;">No Data Available</p>
                <p style="font-size:0.8rem;">Run <code style="background:rgba(255,255,255,0.08); padding:2px 8px; border-radius:4px; font-family:var(--font-mono);">python run_project.py</code> first to generate dashboard data.</p>
            </div>
        `;
    }
}

// ─── Render All ───────────────────────────────────────────────────
function renderAll() {
    if (!dashboardData) return;
    renderStats();
    renderNetworkMap();
    renderAlertFeed();
    renderQuarantineMatrix();
    renderEvaluation();
    renderTestResults();
    renderDeviceRegistry();
    renderFooter();
    setupFilterListeners();
    initSimulator();
}

// ─── Stats ────────────────────────────────────────────────────────
function renderStats() {
    const d = dashboardData;
    animateCounter('totalDevices', d.network.devices.length);
    const totalEvents = Object.values(d.baseline_results || {})
        .reduce((sum, r) => sum + (r.observed || 0), 0);
    animateCounter('totalEvents', totalEvents);
    animateCounter('totalAlerts', d.alerts.length);
    animateCounter('totalQuarantined', (d.quarantined_devices || []).length);

    const passed = d.test_results.filter(t => t.status === 'PASS').length;
    const total = d.test_results.length;
    const testEl = document.getElementById('testsPassed');
    if (testEl) testEl.textContent = `${passed}/${total}`;
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 25));
    const interval = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current;
        if (current >= target) clearInterval(interval);
    }, 30);
}

// ─── Network Map ──────────────────────────────────────────────────
function renderNetworkMap() {
    const container = document.getElementById('networkMap');
    if (!container || !dashboardData) return;
    container.innerHTML = '';

    const quarantinedIPs = new Set((dashboardData.quarantined_devices || []).map(q => q.ip));

    dashboardData.network.devices.forEach((dev, i) => {
        const isQuarantined = quarantinedIPs.has(dev.ip);
        const el = document.createElement('div');
        el.className = `net-device ${isQuarantined ? 'quarantined-node' : ''}`;
        el.id = `node-${dev.ip.replace(/\./g, '_')}`;
        el.style.animationDelay = `${i * 0.08}s`;
        el.innerHTML = `
            <div class="net-device-icon ${dev.role}">
                ${ROLE_ICONS[dev.role] || ROLE_ICONS.unknown}
            </div>
            <div class="net-device-info">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="net-device-name">${dev.name}</span>
                    ${isQuarantined ? '<span class="quarantine-badge" style="font-size:0.6rem; padding:1px 5px;">QUARANTINED</span>' : ''}
                </div>
                <span class="net-device-ip">${dev.ip}</span>
                <span class="net-device-meta">${dev.role} · limit: ${dev.threshold} pkt/5s</span>
            </div>
        `;
        container.appendChild(el);
    });
}

// ─── Alert Feed ───────────────────────────────────────────────────
function renderAlertFeed(filter) {
    const container = document.getElementById('alertFeed');
    if (!container || !dashboardData) return;
    container.innerHTML = '';

    const f = filter || activeFilter;
    const alerts = f === 'all'
        ? dashboardData.alerts
        : dashboardData.alerts.filter(a => a.rule === f);

    if (alerts.length === 0) {
        container.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--text-muted);">
                <p style="font-size:1.5rem; margin-bottom:8px;">✅</p>
                <p>No alerts recorded for this filter category</p>
            </div>
        `;
        return;
    }

    alerts.forEach((alert, i) => {
        const el = document.createElement('div');
        el.className = `alert-item ${alert.rule}`;
        el.style.animationDelay = `${i * 0.04}s`;
        const sev = (alert.severity || 'MEDIUM').toLowerCase();
        el.innerHTML = `
            <span class="alert-icon">${ALERT_ICONS[alert.rule] || '⚠️'}</span>
            <div class="alert-content">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <div class="alert-rule">${formatRule(alert.rule)}</div>
                    <div>
                        <span class="sev-badge sev-${sev}">${alert.severity || 'MEDIUM'}</span>
                        ${alert.quarantined ? '<span class="quarantine-badge" style="margin-left:6px; font-size:0.65rem;">QUARANTINED</span>' : ''}
                    </div>
                </div>
                <div class="alert-detail">${alert.detail}</div>
                <div class="alert-meta">
                    <span>⏱ ${alert.time.toFixed(3)}s</span>
                    <span>📡 ${alert.source} → ${alert.destination} (Port ${alert.dport || '?'})</span>
                    <span>🏷 ${alert.device_name} [${alert.device_role}]</span>
                    ${alert.threat_score ? `<span>⚡ Threat Score: ${alert.threat_score}/100</span>` : ''}
                </div>
            </div>
        `;
        container.appendChild(el);
    });
}

function formatRule(rule) {
    return rule.replace(/_/g, ' ');
}

function setupFilterListeners() {
    const pills = document.querySelectorAll('#alertFilters .pill');
    pills.forEach(pill => {
        pill.addEventListener('click', () => {
            pills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            activeFilter = pill.dataset.filter;
            renderAlertFeed(activeFilter);
        });
    });
}

// ─── Active Defense & Quarantine Matrix ───────────────────────────
function renderQuarantineMatrix() {
    const tbody = document.getElementById('quarantineTableBody');
    if (!tbody || !dashboardData) return;
    tbody.innerHTML = '';

    const mitigations = dashboardData.mitigations || [];
    if (mitigations.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">
                    No active threat quarantines in effect. All nodes within nominal baseline.
                </td>
            </tr>
        `;
        return;
    }

    mitigations.forEach(m => {
        const tr = document.createElement('tr');
        const score = m.threat_score || 70;
        tr.innerHTML = `
            <td style="font-weight:600; color:var(--text-primary);">${m.device_name || 'UNREGISTERED'}</td>
            <td style="font-family:var(--font-mono);">${m.ip}</td>
            <td>
                <div class="threat-meter">
                    <span style="font-family:var(--font-mono); font-weight:700; color:var(--accent-red);">${score}/100</span>
                    <div class="threat-bar">
                        <div class="threat-fill compromised" style="width:${score}%"></div>
                    </div>
                </div>
            </td>
            <td><span class="sev-badge sev-critical">${formatRule(m.trigger_rule || 'POLICY_VIOLATION')}</span></td>
            <td><span class="quarantine-badge">ISOLATED / QUARANTINED</span></td>
            <td><code class="firewall-rule-code">${m.firewall_rule || `iptables -I FORWARD -s ${m.ip} -j DROP`}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

// ─── Evaluation ───────────────────────────────────────────────────
function renderEvaluation() {
    const container = document.getElementById('evalGrid');
    if (!container || !dashboardData?.evaluation) return;
    container.innerHTML = '';

    dashboardData.evaluation.forEach(ev => {
        const el = document.createElement('div');
        el.className = 'eval-card';
        el.innerHTML = `
            <div class="eval-card-title">
                📊 ${capitalize(ev.scenario)}
                <span class="scenario-badge">${ev.total_events} events</span>
            </div>
            <div class="eval-comparison">
                <div class="eval-approach baseline">
                    <div class="eval-approach-label">Baseline (Single T=30)</div>
                    ${renderMetrics(ev.baseline_metrics, ev.baseline_alerts)}
                </div>
                <div class="eval-approach enhanced">
                    <div class="eval-approach-label">Proposed (Per-Device + Rules)</div>
                    ${renderMetrics(ev.enhanced_metrics, ev.enhanced_alerts)}
                </div>
            </div>
        `;
        container.appendChild(el);
    });
}

function renderMetrics(metrics, alertCount) {
    if (!metrics) return '';
    return `
        <div class="eval-metric">
            <span class="eval-metric-label">Alerts</span>
            <span class="eval-metric-value">${alertCount}</span>
        </div>
        <div class="eval-metric">
            <span class="eval-metric-label">Precision</span>
            <span class="eval-metric-value">${formatMetric(metrics.precision)}</span>
        </div>
        <div class="eval-metric">
            <span class="eval-metric-label">Recall</span>
            <span class="eval-metric-value">${formatMetric(metrics.recall)}</span>
        </div>
        <div class="eval-metric">
            <span class="eval-metric-label">FPR</span>
            <span class="eval-metric-value">${formatMetric(metrics.false_positive_rate)}</span>
        </div>
        <div class="eval-metric">
            <span class="eval-metric-label">TP/FP/FN/TN</span>
            <span class="eval-metric-value">${metrics.TP}/${metrics.FP}/${metrics.FN}/${metrics.TN}</span>
        </div>
    `;
}

function formatMetric(val) {
    if (val === 'N/A' || val === null || val === undefined) return 'N/A';
    if (typeof val === 'number') return (val * 100).toFixed(1) + '%';
    return String(val);
}

// ─── Test Results ─────────────────────────────────────────────────
function renderTestResults() {
    const tbody = document.getElementById('testTableBody');
    const summaryEl = document.getElementById('testSummaryBadge');
    if (!tbody || !dashboardData?.test_results) return;
    tbody.innerHTML = '';

    const tests = dashboardData.test_results;
    const passed = tests.filter(t => t.status === 'PASS').length;
    const failed = tests.filter(t => t.status === 'FAIL').length;

    if (summaryEl) {
        summaryEl.innerHTML = `
            <span class="test-count passed">✓ ${passed} Passed</span>
            ${failed > 0 ? `<span class="test-count failed">✗ ${failed} Failed</span>` : ''}
        `;
    }

    tests.forEach(test => {
        const tr = document.createElement('tr');
        const statusClass = test.status === 'PASS' ? 'pass' : 'fail';
        const statusIcon = test.status === 'PASS' ? '✓' : '✗';
        tr.innerHTML = `
            <td>${test.test_id}</td>
            <td style="font-weight:600;">${test.name}</td>
            <td style="font-size:0.75rem; color:var(--text-secondary)">${test.condition}</td>
            <td style="font-size:0.75rem; color:var(--text-secondary)">${test.expected}</td>
            <td style="font-size:0.75rem; font-family:var(--font-mono)">${test.actual}</td>
            <td><span class="test-status ${statusClass}">${statusIcon} ${test.status}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// ─── Device Registry ──────────────────────────────────────────────
function renderDeviceRegistry() {
    const container = document.getElementById('deviceGrid');
    const countEl = document.getElementById('deviceCount');
    if (!container || !dashboardData?.network) return;
    container.innerHTML = '';

    const devices = dashboardData.network.devices;
    if (countEl) countEl.textContent = `${devices.length} registered`;

    const quarantinedIPs = new Set((dashboardData.quarantined_devices || []).map(q => q.ip));

    devices.forEach((dev, i) => {
        const isQuarantined = quarantinedIPs.has(dev.ip);
        const el = document.createElement('div');
        el.className = `device-card ${dev.role}`;
        el.style.animationDelay = `${i * 0.08}s`;

        const portsHtml = (dev.allowed_ports && dev.allowed_ports.length > 0)
            ? dev.allowed_ports.map(p => `<span class="port-tag">${p}</span>`).join('')
            : '<span style="color:var(--text-muted); font-size:0.72rem;">Any</span>';

        el.innerHTML = `
            <div class="device-card-header">
                <span class="device-card-icon">${ROLE_ICONS[dev.role] || '❓'}</span>
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div class="device-card-title">${dev.name}</div>
                    </div>
                    <div class="device-card-role">${dev.role}</div>
                </div>
            </div>
            <div class="device-card-details">
                <div class="device-detail">
                    <span class="device-detail-label">IP Address</span>
                    <span class="device-detail-value">${dev.ip}</span>
                </div>
                <div class="device-detail">
                    <span class="device-detail-label">Burst Limit</span>
                    <span class="device-detail-value">${dev.threshold} pkt/5s</span>
                </div>
                <div class="device-detail" style="grid-column: span 2;">
                    <span class="device-detail-label">Allowed Service Ports</span>
                    <div style="margin-top:4px;">${portsHtml}</div>
                </div>
                <div class="device-detail" style="grid-column: span 2;">
                    <span class="device-detail-label">Security Assessment</span>
                    <div>${isQuarantined ? '<span class="quarantine-badge">QUARANTINED</span>' : '<span style="color:var(--accent-green); font-size:0.75rem; font-weight:600;">✓ SECURE & VERIFIED</span>'}</div>
                </div>
            </div>
            ${dev.description ? `<div class="device-card-desc">${dev.description}</div>` : ''}
        `;
        container.appendChild(el);
    });
}

// ─── Interactive Scenario Simulator ───────────────────────────────
function initSimulator() {
    const select = document.getElementById('scenarioSelect');
    const playBtn = document.getElementById('simPlayBtn');
    const resetBtn = document.getElementById('simResetBtn');
    const slider = document.getElementById('simSlider');

    if (!select || !playBtn || !resetBtn || !slider) return;

    select.addEventListener('change', () => {
        resetSimulation();
    });

    playBtn.addEventListener('click', () => {
        if (simInterval) {
            pauseSimulation();
        } else {
            startSimulation();
        }
    });

    resetBtn.addEventListener('click', () => {
        resetSimulation();
    });

    slider.addEventListener('input', (e) => {
        pauseSimulation();
        seekSimulation(parseInt(e.target.value));
    });

    loadScenarioEvents(select.value);
}

function loadScenarioEvents(scenarioName) {
    if (!dashboardData?.scenario_events) return;
    currentScenarioEvents = dashboardData.scenario_events[scenarioName] || [];
    const slider = document.getElementById('simSlider');
    if (slider) {
        slider.max = Math.max(0, currentScenarioEvents.length - 1);
        slider.value = 0;
    }
    updateSimStats(0);
}

function startSimulation() {
    const playBtn = document.getElementById('simPlayBtn');
    if (!playBtn) return;
    playBtn.textContent = '⏸ Pause';
    playBtn.className = 'sim-btn sim-btn-secondary';

    const events = currentScenarioEvents;
    if (events.length === 0) return;

    simInterval = setInterval(() => {
        if (simIndex >= events.length) {
            pauseSimulation();
            return;
        }
        stepSimulation(simIndex);
        simIndex++;
        const slider = document.getElementById('simSlider');
        if (slider) slider.value = simIndex;
    }, 150);
}

function pauseSimulation() {
    clearInterval(simInterval);
    simInterval = null;
    const playBtn = document.getElementById('simPlayBtn');
    if (playBtn) {
        playBtn.textContent = '▶ Play Replay';
        playBtn.className = 'sim-btn sim-btn-primary';
    }
}

function resetSimulation() {
    pauseSimulation();
    simIndex = 0;
    const select = document.getElementById('scenarioSelect');
    if (select) loadScenarioEvents(select.value);
    const ticker = document.getElementById('packetTicker');
    if (ticker) {
        ticker.innerHTML = '<div class="ticker-item" style="color:var(--text-muted);">Simulation reset. Ready to play...</div>';
    }
    document.querySelectorAll('.net-device').forEach(n => n.classList.remove('active-source'));
    const slider = document.getElementById('simSlider');
    if (slider) slider.value = 0;
}

function seekSimulation(index) {
    simIndex = Math.min(index, currentScenarioEvents.length - 1);
    stepSimulation(simIndex);
}

function stepSimulation(idx) {
    if (!currentScenarioEvents[idx]) return;
    const ev = currentScenarioEvents[idx];
    updateSimStats(idx);

    // Pulse node
    document.querySelectorAll('.net-device').forEach(n => n.classList.remove('active-source'));
    const srcNode = document.getElementById(`node-${ev.src.replace(/\./g, '_')}`);
    if (srcNode) {
        srcNode.classList.add('active-source');
    }

    // Add to ticker
    const ticker = document.getElementById('packetTicker');
    if (ticker) {
        const item = document.createElement('div');
        const isSuspicious = ev.label === 'suspicious';
        item.className = `ticker-item ${isSuspicious ? 'alert-event' : ''}`;
        item.innerHTML = `
            <span>[${ev.elapsed_s.toFixed(2)}s] ${ev.src} → ${ev.dst} :${ev.dport} (${ev.protocol})</span>
            <span>${isSuspicious ? '⚠️ ANOMALOUS' : '✓ NORMAL'}</span>
        `;
        ticker.prepend(item);
        if (ticker.children.length > 20) {
            ticker.removeChild(ticker.lastChild);
        }
    }
}

function updateSimStats(idx) {
    const statsEl = document.getElementById('simStats');
    if (!statsEl) return;
    const ev = currentScenarioEvents[idx];
    const time = ev ? ev.elapsed_s.toFixed(1) : '0.0';
    statsEl.textContent = `${time}s | Pkt ${idx + 1}/${currentScenarioEvents.length}`;
}

// ─── Footer ───────────────────────────────────────────────────────
function renderFooter() {
    const el = document.getElementById('footerMeta');
    if (!el || !dashboardData) return;
    el.textContent = `Generated: ${dashboardData.generated_at} · Python ${dashboardData.python_version?.split(' ')[0] || '?'} · ${dashboardData.platform || '?'}`;
}

// ─── Helpers ──────────────────────────────────────────────────────
function capitalize(s) {
    return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
