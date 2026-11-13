// Chart.js Visualization Module for Snort NIDS Dashboard

let trendChartInstance = null;
let protocolChartInstance = null;
let attackTypesChartInstance = null;

function renderTrendChart(trendData) {
    const ctx = document.getElementById('chartTrend');
    if (!ctx) return;

    if (trendChartInstance) {
        trendChartInstance.destroy();
    }

    trendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trendData.labels,
            datasets: [{
                label: 'Intrusions Detected',
                data: trendData.counts,
                borderColor: '#00f2fe',
                backgroundColor: 'rgba(0, 242, 254, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointBackgroundColor: '#00f2fe',
                pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: '#1e293b' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { color: '#1e293b' },
                    ticks: { color: '#94a3b8', stepSize: 1 },
                    beginAtZero: true
                }
            }
        }
    });
}

function renderProtocolChart(protocolData) {
    const ctx = document.getElementById('chartProtocol');
    if (!ctx) return;

    if (protocolChartInstance) {
        protocolChartInstance.destroy();
    }

    const labels = Object.keys(protocolData);
    const counts = Object.values(protocolData);

    protocolChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: [
                    '#3b82f6', // TCP - Blue
                    '#10b981', // UDP - Green
                    '#f59e0b', // ICMP - Amber
                    '#8b5cf6'  # DNS / Other - Purple
                ],
                borderWidth: 1,
                borderColor: '#0f172a'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', boxWidth: 12 }
                }
            }
        }
    });
}

function renderAttackTypesChart(attackData) {
    const ctx = document.getElementById('chartAttackTypes');
    if (!ctx) return;

    if (attackTypesChartInstance) {
        attackTypesChartInstance.destroy();
    }

    const labels = Object.keys(attackData);
    const counts = Object.values(attackData);

    attackTypesChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Occurrences',
                data: counts,
                backgroundColor: 'rgba(245, 158, 11, 0.6)',
                borderColor: '#f59e0b',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { color: '#1e293b' },
                    ticks: { color: '#94a3b8', stepSize: 1 },
                    beginAtZero: true
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 10 } }
                }
            }
        }
    });
}
