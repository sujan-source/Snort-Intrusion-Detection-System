// Lab Attack Simulator JS

document.addEventListener('DOMContentLoaded', () => {
    const buttons = document.querySelectorAll('.btn-trigger-attack');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            const attackType = btn.getAttribute('data-attack');
            triggerAttack(attackType);
        });
    });
});

async function triggerAttack(attackType) {
    const consoleBox = document.getElementById('simLogConsole');
    logToConsole(`[>] Launching synthetic attack vector: ${attackType.toUpperCase()}...`);

    try {
        const res = await fetch('/api/simulation/trigger', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                attack_type: attackType,
                target_ip: '192.168.1.100',
                source_ip: '10.0.0.45'
            })
        });

        if (!res.ok) {
            logToConsole(`[!] Simulation failed: ${res.statusText}`);
            return;
        }

        const alert = await res.json();
        logToConsole(`[✓] SUCCESS: Snort Signature Match Triggered! Alert ID: #${alert.id} | SID: ${alert.sid} | Msg: "${alert.msg}"`);
        logToConsole(`[+] Raw Snort Alert String: ${alert.raw_alert}`);
    } catch (e) {
        logToConsole(`[!] Exception during attack execution: ${e.message}`);
    }
}

function logToConsole(message) {
    const consoleBox = document.getElementById('simLogConsole');
    if (!consoleBox) return;

    const timeStr = new Date().toLocaleTimeString();
    const line = `[${timeStr}] ${message}\n`;
    consoleBox.innerText += line;
    consoleBox.scrollTop = consoleBox.scrollHeight;
}
