// Executive Security Reports JS

document.addEventListener('DOMContentLoaded', () => {
    loadReportSummary();
});

async function loadReportSummary() {
    try {
        const res = await fetch('/api/reports/summary?days=7');
        if (!res.ok) return;
        const data = await res.json();

        const container = document.getElementById('reportContainer');
        if (!container) return;

        const m = data.metrics;

        container.innerHTML = `
            <div class="row g-3 mb-4">
                <div class="col-6 col-md-3">
                    <div class="p-3 bg-dark rounded border border-secondary text-center">
                        <div class="text-secondary small">Total Alerts</div>
                        <div class="fs-4 fw-bold text-light">${m.total_alerts}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-3 bg-dark rounded border border-secondary text-center">
                        <div class="text-secondary small">Critical Severity</div>
                        <div class="fs-4 fw-bold text-danger">${m.critical}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-3 bg-dark rounded border border-secondary text-center">
                        <div class="text-secondary small">High Severity</div>
                        <div class="fs-4 fw-bold text-warning">${m.high}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-3 bg-dark rounded border border-secondary text-center">
                        <div class="text-secondary small">Resolved Incidents</div>
                        <div class="fs-4 fw-bold text-success">${m.resolved}</div>
                    </div>
                </div>
            </div>

            <div class="row g-4 mb-4">
                <div class="col-md-6">
                    <h6 class="text-uppercase fw-bold text-info mb-3">Top Attack Vectors Detected</h6>
                    <ul class="list-group list-group-flush bg-transparent">
                        ${data.attack_types.map(a => `
                            <li class="list-group-item bg-transparent text-light border-secondary d-flex justify-content-between align-items-center">
                                <span class="fw-semibold text-light">${a.type}</span>
                                <span class="badge badge-yellow-box">${a.count} occurrences</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
                <div class="col-md-6">
                    <h6 class="text-uppercase fw-bold text-danger mb-3">Most Active Threat Source IPs</h6>
                    <ul class="list-group list-group-flush bg-transparent">
                        ${data.top_sources.map(s => `
                            <li class="list-group-item bg-transparent text-light border-secondary d-flex justify-content-between align-items-center">
                                <span class="font-monospace text-cyan fw-bold">${s.ip}</span>
                                <span class="badge badge-red-box">${s.count} alerts</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            </div>

            <h6 class="text-uppercase fw-bold text-success mb-3"><i class="fa-solid fa-shield-halved me-2"></i> Automated Defensive Action Recommendations</h6>
            <div class="accordion accordion-flush" id="accDefenses">
                ${data.defensive_actions.map((act, idx) => `
                    <div class="accordion-item bg-dark text-light border border-secondary mb-2 rounded">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed bg-dark text-info font-semibold" type="button" data-bs-toggle="collapse" data-bs-target="#collapse${idx}">
                                <i class="fa-solid fa-lock me-2 text-warning"></i> Defense Plan for: ${act.attack_type} (${act.incident_count} Incidents)
                            </button>
                        </h2>
                        <div id="collapse${idx}" class="accordion-collapse collapse" data-bs-parent="#accDefenses">
                            <div class="accordion-body text-secondary small">
                                <ul class="mb-0">
                                    ${act.recommendations.map(r => `<li class="mb-1">${r}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        console.error('Failed to load report summary:', e);
    }
}
