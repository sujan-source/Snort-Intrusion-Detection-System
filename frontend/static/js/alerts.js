// Alert Feed Page & Incident Investigation JS

let currentPage = 1;

document.addEventListener('DOMContentLoaded', () => {
    checkUserAuth();
    fetchAlertsPage(1);

    document.getElementById('filterForm').addEventListener('submit', (e) => {
        e.preventDefault();
        fetchAlertsPage(1);
    });

    document.getElementById('btnResetFilters').addEventListener('click', () => {
        document.getElementById('inputSearch').value = '';
        document.getElementById('selectSeverity').value = '';
        document.getElementById('selectProtocol').value = '';
        document.getElementById('selectStatus').value = '';
        fetchAlertsPage(1);
    });
});

async function fetchAlertsPage(page = 1) {
    currentPage = page;
    const search = document.getElementById('inputSearch').value;
    const severity = document.getElementById('selectSeverity').value;
    const protocol = document.getElementById('selectProtocol').value;
    const status = document.getElementById('selectStatus').value;

    const params = new URLSearchParams({
        page: page,
        page_size: 10
    });

    if (search) params.append('search', search);
    if (severity) params.append('severity', severity);
    if (protocol) params.append('protocol', protocol);
    if (status) params.append('status', status);

    try {
        const res = await fetch(`/api/alerts?${params.toString()}`);
        if (!res.ok) return;
        const data = await res.json();

        renderAlertsTable(data.alerts);
        renderPaginationControls(data.page, data.total_pages, data.total);
    } catch (e) {
        console.error('Failed to fetch alerts page:', e);
    }
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById('tbodyAlertsList');
    if (!tbody) return;

    if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-4">No matching alerts found.</td></tr>';
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        const sevClass = getSeverityBadgeClass(a.severity);
        const statusClass = getStatusBadgeClass(a.status);
        const tsFormatted = new Date(a.timestamp).toLocaleString();
        const srcStr = a.source_port ? `${a.source_ip}:${a.source_port}` : a.source_ip;
        const dstStr = a.destination_port ? `${a.destination_ip}:${a.destination_port}` : a.destination_ip;

        return `
            <tr>
                <td class="font-monospace text-cyan fw-bold">#${a.id}</td>
                <td class="font-monospace text-secondary small">${tsFormatted}</td>
                <td><span class="badge ${sevClass}">${a.severity}</span></td>
                <td><span class="badge bg-dark border border-secondary text-info fw-bold">${a.protocol}</span></td>
                <td class="font-monospace text-cyan fw-semibold">${srcStr}</td>
                <td class="font-monospace text-cyan fw-semibold">${dstStr}</td>
                <td>
                    <div class="fw-bold text-light">${a.attack_type}</div>
                    <div class="text-secondary small">${a.msg}</div>
                </td>
                <td><span class="badge ${statusClass}">${a.status}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-info px-3" onclick="openTriageModal(${a.id})">
                        <i class="fa-solid fa-user-pen me-1"></i> Triage
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderPaginationControls(page, totalPages, totalCount) {
    document.getElementById('lblPaginationSummary').textContent = `Page ${page} of ${totalPages} (${totalCount} total alerts)`;
    const pagination = document.getElementById('paginationControls');

    let html = '';
    const prevDisabled = page <= 1 ? 'disabled' : '';
    const nextDisabled = page >= totalPages ? 'disabled' : '';

    html += `<li class="page-item ${prevDisabled}"><a class="page-link bg-dark border-secondary text-light" href="#" onclick="fetchAlertsPage(${page - 1})">Prev</a></li>`;

    for (let p = 1; p <= totalPages; p++) {
        const active = p === page ? 'active' : '';
        html += `<li class="page-item ${active}"><a class="page-link bg-dark border-secondary text-light" href="#" onclick="fetchAlertsPage(${p})">${p}</a></li>`;
    }

    html += `<li class="page-item ${nextDisabled}"><a class="page-link bg-dark border-secondary text-light" href="#" onclick="fetchAlertsPage(${page + 1})">Next</a></li>`;

    pagination.innerHTML = html;
}

function getSeverityBadgeClass(severity) {
    switch ((severity || '').toLowerCase()) {
        case 'critical': return 'badge-critical';
        case 'high': return 'badge-high';
        case 'medium': return 'badge-medium';
        default: return 'badge-low';
    }
}

function getStatusBadgeClass(status) {
    switch ((status || '').toLowerCase()) {
        case 'new': return 'status-new';
        case 'investigating': return 'status-investigating';
        case 'resolved': return 'status-resolved';
        default: return 'status-false_positive';
    }
}

async function openTriageModal(alertId) {
    try {
        const res = await fetch(`/api/alerts/${alertId}`);
        if (!res.ok) return;
        const alert = await res.json();

        const modalBody = document.getElementById('modalBody');
        const modal = new bootstrap.Modal(document.getElementById('modalAlertDetail'));

        modalBody.innerHTML = `
            <div class="row g-3 mb-3">
                <div class="col-md-6">
                    <span class="text-secondary small">Alert ID & SID:</span>
                    <div class="fw-bold text-info">Alert #${alert.id} &bull; SID: ${alert.sid}:${alert.rev}</div>
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
                    <span class="text-secondary small">Source -> Destination:</span>
                    <div class="font-monospace text-cyan fw-semibold">${alert.source_ip} -> ${alert.destination_ip}</div>
                </div>
            </div>

            <div class="mb-3">
                <span class="text-secondary small">Rule Message:</span>
                <div class="p-2 bg-dark rounded border border-secondary text-warning fw-semibold">${alert.msg}</div>
            </div>

            <div class="mb-3">
                <span class="text-secondary small">Raw Snort Log String:</span>
                <div class="code-box">${alert.raw_alert || 'N/A'}</div>
            </div>

            <form id="formUpdateStatus" class="p-3 bg-dark rounded border border-secondary mt-3">
                <h6 class="text-light fw-bold mb-3"><i class="fa-solid fa-pen-to-square me-1 text-info"></i> Update Alert Status & Add Investigation Notes</h6>
                <div class="mb-3">
                    <label class="form-label text-secondary small">Status Selection</label>
                    <select id="updateStatusSelect" class="form-select form-select-sm bg-dark border-secondary text-light">
                        <option value="New" ${alert.status === 'New' ? 'selected' : ''}>New</option>
                        <option value="Investigating" ${alert.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                        <option value="Resolved" ${alert.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                        <option value="False Positive" ${alert.status === 'False Positive' ? 'selected' : ''}>False Positive</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label class="form-label text-secondary small">Analyst Comments / Remediation Notes</label>
                    <textarea id="updateNotesInput" class="form-control form-control-sm bg-dark border-secondary text-light" rows="2" placeholder="Add investigation notes..."></textarea>
                </div>
                ${alert.notes ? `<div class="mb-3 text-secondary small"><strong>Past Notes History:</strong><br><pre class="text-info font-monospace small bg-black p-2 rounded">${alert.notes}</pre></div>` : ''}
                <button type="submit" class="btn btn-sm btn-info w-100"><i class="fa-solid fa-floppy-disk me-1"></i> Save Incident Status</button>
            </form>
        `;

        modal.show();

        document.getElementById('formUpdateStatus').addEventListener('submit', async (e) => {
            e.preventDefault();
            const newStatus = document.getElementById('updateStatusSelect').value;
            const newNotes = document.getElementById('updateNotesInput').value;

            const token = localStorage.getItem('nids_token');
            const headers = {'Content-Type': 'application/json'};
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const updateRes = await fetch(`/api/alerts/${alertId}/status`, {
                method: 'PATCH',
                headers: headers,
                body: JSON.stringify({ status: newStatus, notes: newNotes })
            });

            if (updateRes.ok) {
                modal.hide();
                fetchAlertsPage(currentPage);
            } else {
                alert('Failed to update status. Ensure you are logged in.');
            }
        });
    } catch (e) {
        console.error('Failed to load alert detail:', e);
    }
}

function checkUserAuth() {
    const username = localStorage.getItem('nids_username');
    if (username) {
        const lbl = document.getElementById('lblUsername');
        if (lbl) lbl.textContent = username;
    }
}

function handleLogout(event) {
    if (event) event.preventDefault();
    localStorage.removeItem('nids_token');
    localStorage.removeItem('nids_username');
    localStorage.removeItem('nids_role');
    window.location.href = '/login';
}
