// Snort Rules Manager JS

document.addEventListener('DOMContentLoaded', () => {
    checkUserAuth();
    loadRules();

    const formAdd = document.getElementById('formAddRule');
    if (formAdd) {
        formAdd.addEventListener('submit', async (e) => {
            e.preventDefault();
            const sid = parseInt(document.getElementById('newSid').value);
            const protocol = document.getElementById('newProtocol').value;
            const severity = document.getElementById('newSeverity').value;
            const msg = document.getElementById('newMsg').value;
            const raw = document.getElementById('newRawRule').value;

            const token = localStorage.getItem('nids_token');
            const headers = {'Content-Type': 'application/json'};
            if (token) headers['Authorization'] = `Bearer ${token}`;

            try {
                const res = await fetch('/api/rules', {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify({
                        sid: sid,
                        protocol: protocol,
                        severity: severity,
                        msg: msg,
                        raw_rule: raw,
                        is_active: true
                    })
                });

                if (res.ok) {
                    const modalEl = document.getElementById('modalAddRule');
                    const modal = bootstrap.Modal.getInstance(modalEl);
                    modal.hide();
                    formAdd.reset();
                    loadRules();
                } else {
                    const err = await res.json();
                    alert(err.detail || 'Failed to save Snort rule. Ensure you have admin access.');
                }
            } catch (ex) {
                alert('Connection error saving rule.');
            }
        });
    }
});

async function loadRules() {
    try {
        const res = await fetch('/api/rules');
        if (!res.ok) return;
        const rules = await res.json();

        const tbody = document.getElementById('tbodyRules');
        if (!tbody) return;

        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No Snort rules registered.</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(r => `
            <tr>
                <td class="font-monospace text-info">SID:${r.sid}</td>
                <td class="text-secondary small">${r.rev}</td>
                <td><span class="badge bg-dark border border-secondary text-info">${r.protocol.toUpperCase()}</span></td>
                <td>
                    <div class="fw-semibold text-light">${r.msg}</div>
                </td>
                <td class="text-secondary small">${r.category}</td>
                <td><span class="badge ${getSeverityBadgeClass(r.severity)}">${r.severity}</span></td>
                <td>
                    <button class="btn btn-sm ${r.is_active ? 'btn-success' : 'btn-outline-secondary'}" onclick="toggleRuleActive(${r.id})">
                        ${r.is_active ? '<i class="fa-solid fa-check me-1"></i> Active' : '<i class="fa-solid fa-xmark me-1"></i> Disabled'}
                    </button>
                </td>
                <td>
                    <div class="code-box extra-small">${r.raw_rule}</div>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to load rules:', e);
    }
}

async function toggleRuleActive(ruleId) {
    const token = localStorage.getItem('nids_token');
    const headers = {'Content-Type': 'application/json'};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
        const res = await fetch(`/api/rules/${ruleId}/toggle`, {
            method: 'POST',
            headers: headers
        });
        if (res.ok) {
            loadRules();
        } else {
            alert('Admin privilege required to modify Snort rules.');
        }
    } catch (e) {
        console.error('Failed to toggle rule state:', e);
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
