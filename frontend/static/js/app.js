// Main Dashboard Logic for Snort NIDS

document.addEventListener('DOMContentLoaded', () => {
    checkUserAuth();
    loadSummaryMetrics();
    loadChartsData();
    loadTopAttackers();
    loadLiveAlertsStream();

    // Auto-refresh stats every 4 seconds for real-time monitoring
    setInterval(() => {
        loadSummaryMetrics();
        loadChartsData();
        loadLiveAlertsStream();
    }, 4000);
});

function checkUserAuth() {
    const username = localStorage.getItem('nids_username');
    if (username) {
        document.getElementById('lblUsername').textContent = username;
    }
}

async function loadSummaryMetrics() {
    try {
        const res = await fetch('/api/stats/summary');
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('valTotalPackets').textContent = data.total_packets_monitored.toLocaleString();
        document.getElementById('valTotalIntrusions').textContent = data.total_intrusions_detected.toLocaleString();
        document.getElementById('valCritical').textContent = data.severity.critical;
        document.getElementById('valHighMed').textContent = data.severity.high + data.severity.medium;
    } catch (e) {
        console.error('Failed to load metrics:', e);
    }
}

async function loadChartsData() {
    try {
        const res = await fetch('/api/stats/charts');
        if (!res.ok) return;
        const data = await res.json();

        if (typeof renderTrendChart === 'function') {
            renderTrendChart(data.trend);
            renderProtocolChart(data.protocol_distribution);
            renderAttackTypesChart(data.attack_type_distribution);
        }
    } catch (e) {
        console.error('Failed to load charts:', e);
    }
}

async function loadTopAttackers() {
    try {
        const res = await fetch('/api/stats/top-ips');
        if (!res.ok) return;
        const data = await res.json();

        const container = document.getElementById('listTopSources');
        if (!container) return;

        if (data.top_sources.length === 0) {
            container.innerHTML = '<div class="text-muted small">No attacker IP data available.</div>';
            return;
        }

        container.innerHTML = data.top_sources.map((item, idx) => `
            <div class="d-flex justify-content-between align-items-center mb-2 pb-2 border-bottom border-secondary">
                <div class="d-flex align-items-center">
                    <span class="badge bg-dark border border-secondary text-info me-2">#${idx + 1}</span>
                    <span class="font-monospace small text-cyan fw-semibold">${item.ip}</span>
                </div>
                <span class="badge badge-red-box">${item.count} attacks</span>
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to load top attackers:', e);
    }
}

async function loadLiveAlertsStream() {
    try {
        const res = await fetch('/api/alerts?page=1&page_size=7');
        if (!res.ok) return;
        const data = await res.json();

        const tbody = document.getElementById('tbodyLiveAlerts');
        if (!tbody) return;

        if (data.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No security alerts detected yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.alerts.map(a => {
            const sevClass = getSeverityBadgeClass(a.severity);
            const tsFormatted = new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            const srcStr = a.source_port ? `${a.source_ip}:${a.source_port}` : a.source_ip;
            const dstStr = a.destination_port ? `${a.destination_ip}:${a.destination_port}` : a.destination_ip;

            return `
                <tr>
                    <td class="font-monospace text-secondary small">${tsFormatted}</td>
                    <td><span class="badge ${sevClass}">${a.severity}</span></td>
                    <td><span class="badge bg-dark border border-secondary text-info fw-bold">${a.protocol}</span></td>
                    <td class="font-monospace text-cyan fw-semibold">${srcStr}</td>
                    <td class="font-monospace text-cyan fw-semibold">${dstStr}</td>
                    <td>
                        <div class="fw-bold text-light">${a.attack_type}</div>
                        <div class="text-secondary small">${a.msg}</div>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-outline-info" onclick="viewAlertDetail(${a.id})">
                            <i class="fa-solid fa-eye"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('Failed to load live alerts:', e);
    }
}

function getSeverityBadgeClass(severity) {
    switch ((severity || '').toLowerCase()) {
        case 'critical': return 'badge-critical';
        case 'high': return 'badge-high';
        case 'medium': return 'badge-medium';
        default: return 'badge-low';
    }
}

async function viewAlertDetail(alertId) {
    try {
        const res = await fetch(`/api/alerts/${alertId}`);
        if (!res.ok) return;
        const alert = await res.json();

        const modalBody = document.getElementById('modalBody');
        const modal = new bootstrap.Modal(document.getElementById('modalAlertDetail'));

        modalBody.innerHTML = `
            <div class="row g-3 mb-3">
                <div class="col-md-6">
                    <span class="text-secondary small">Alert ID:</span>
                    <div class="fw-bold text-light">#${alert.id}</div>
                </div>
                <div class="col-md-6">
                    <span class="text-secondary small">Snort Signature (SID:REV):</span>
                    <div class="fw-bold text-info">${alert.sid}:${alert.rev}</div>
                </div>
                <div class="col-md-6">
                    <span class="text-secondary small">Timestamp:</span>
                    <div class="text-light">${new Date(alert.timestamp).toLocaleString()}</div>
                </div>
                <div class="col-md-6">
                    <span class="text-secondary small">Severity / Protocol:</span>
                    <div>
                        <span class="badge ${getSeverityBadgeClass(alert.severity)} me-1">${alert.severity}</span>
                        <span class="badge bg-dark border border-secondary text-info">${alert.protocol}</span>
                    </div>
                </div>
                <div class="col-md-6">
                    <span class="text-secondary small">Source IP & Port:</span>
                    <div class="font-monospace text-cyan fw-semibold">${alert.source_ip}${alert.source_port ? ':' + alert.source_port : ''}</div>
                </div>
                <div class="col-md-6">
                    <span class="text-secondary small">Destination IP & Port:</span>
                    <div class="font-monospace text-cyan fw-semibold">${alert.destination_ip}${alert.destination_port ? ':' + alert.destination_port : ''}</div>
                </div>
            </div>

            <div class="mb-3">
                <span class="text-secondary small">Snort Alert Message:</span>
                <div class="p-2 bg-dark rounded border border-secondary text-warning fw-semibold">${alert.msg}</div>
            </div>

            <div class="mb-3">
                <span class="text-secondary small">Raw Snort Log String:</span>
                <div class="code-box">${alert.raw_alert || 'N/A'}</div>
            </div>

            <div class="p-3 bg-dark bg-opacity-50 rounded border border-secondary">
                <h6 class="text-light fw-bold mb-2"><i class="fa-solid fa-user-gear me-1 text-info"></i> Triage & Incident Investigation</h6>
                <div class="mb-2">
                    <span class="text-secondary small me-2">Current Status:</span>
                    <span class="badge bg-info text-dark">${alert.status}</span>
                </div>
                ${alert.notes ? `<div class="text-secondary small mb-2"><strong>Analyst Notes:</strong><br>${alert.notes.replace(/\n/g, '<br>')}</div>` : ''}
                <a href="/alerts-page" class="btn btn-sm btn-outline-info mt-2">Manage Status & Add Notes in Alerts Panel</a>
            </div>
        `;

        modal.show();
    } catch (e) {
        console.error('Failed to load alert detail:', e);
    }
}
