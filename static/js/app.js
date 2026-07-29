/* ============================================
   reconFTW WebUI — Main Application
   ============================================ */

'use strict';

// ============ STATE ============
const state = {
    socket: null,
    connected: false,
    currentScan: null,
    scanStartTime: null,
    scanTimer: null,
    outputLines: 0,
    currentView: 'scanner',
    results: [],
    configOriginal: '',
    activeTab: null,
    terminalLines: [],
};

// ============ SOCKET.IO INIT ============
function initSocket() {
    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('connect', () => {
        state.connected = true;
        updateConnectionStatus(true);
        showToast('Connected to reconFTW server', 'success');
        loadResults();
    });

    state.socket.on('disconnect', () => {
        state.connected = false;
        updateConnectionStatus(false);
        showToast('Disconnected from server', 'error');
    });

    state.socket.on('connected', (data) => {
        console.log('Server:', data.status);
    });

    state.socket.on('scan_started', (data) => {
        onScanStarted(data);
    });

    state.socket.on('scan_pid', (data) => {
        state.currentScan = { ...state.currentScan, pid: data.pid };
    });

    state.socket.on('scan_output', (data) => {
        appendTerminalLine(data.line);
        state.outputLines++;
        updateProgressStats();
    });

    state.socket.on('scan_completed', (data) => {
        onScanCompleted(data);
    });

    state.socket.on('scan_stopped', (data) => {
        onScanStopped(data);
    });

    state.socket.on('scan_error', (data) => {
        showToast(data.message, 'error');
        resetScanUI();
    });

    state.socket.on('results_update', (data) => {
        state.results = data.results;
        renderResults();
    });
}

// ============ CONNECTION STATUS ============
function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('conn-status');
    const dot = statusEl.querySelector('.status-dot');
    const text = statusEl.querySelector('span:last-child');

    if (connected) {
        dot.className = 'status-dot online';
        text.textContent = 'Connected';
    } else {
        dot.className = 'status-dot offline';
        text.textContent = 'Disconnected';
    }
}

// ============ NAVIGATION ============
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            switchView(view);
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
        });
    });
}

function switchView(viewName) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const view = document.getElementById(`view-${viewName}`);
    if (view) {
        view.classList.add('active');
        state.currentView = viewName;
    }

    // Load data for specific views
    if (viewName === 'results') loadResults();
    if (viewName === 'config') loadConfig();
    if (viewName === 'tools') checkTools();
}

// ============ COMMAND PREVIEW ============
function updateCommandPreview() {
    const target = document.getElementById('target-input').value.trim() || '<target>';
    const mode = getSelectedMode();
    const deep = document.getElementById('opt-deep').checked;
    const ai = document.getElementById('opt-ai').checked;
    const incremental = document.getElementById('opt-incremental').checked;
    const noParallel = document.getElementById('opt-no-parallel').checked;
    const rateLimit = document.getElementById('rate-limit').value.trim();
    const inscope = document.getElementById('inscope-input').value.trim();
    const outscope = document.getElementById('outscope-input').value.trim();
    const output = document.getElementById('output-input').value.trim();

    const modeFlags = {
        recon: '-r', all: '-a', passive: '-p',
        subdomains: '-s', web: '-w', osint: '-n', zen: '-z'
    };

    let cmd = `./reconftw.sh -d ${target} ${modeFlags[mode] || '-r'}`;
    if (deep) cmd += ' --deep';
    if (ai) cmd += ' --ai';
    if (incremental) cmd += ' --incremental';
    if (noParallel) cmd += ' --no-parallel';
    if (rateLimit) cmd += ` -q ${rateLimit}`;
    if (inscope) cmd += ` -i ${inscope}`;
    if (outscope) cmd += ` -x ${outscope}`;
    if (output) cmd += ` -o ${output}`;

    document.getElementById('cmd-text').textContent = cmd;
}

function getSelectedMode() {
    const radio = document.querySelector('input[name="scan-mode"]:checked');
    return radio ? radio.value : 'recon';
}

// ============ MODE SELECTION ============
function initModeSelection() {
    document.querySelectorAll('.mode-option').forEach(option => {
        option.addEventListener('click', () => {
            document.querySelectorAll('.mode-option').forEach(o => o.classList.remove('selected'));
            option.classList.add('selected');
            option.querySelector('input').checked = true;
            updateCommandPreview();
        });
    });
}

// ============ SCAN ACTIONS ============
function initScanActions() {
    document.getElementById('btn-start-scan').addEventListener('click', startScan);
    document.getElementById('btn-stop-scan').addEventListener('click', stopScan);
    document.getElementById('copy-cmd').addEventListener('click', () => {
        const cmd = document.getElementById('cmd-text').textContent;
        navigator.clipboard.writeText(cmd).then(() => showToast('Command copied!', 'info'));
    });

    // Auto-update preview
    ['target-input', 'inscope-input', 'outscope-input', 'output-input', 'rate-limit'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', updateCommandPreview);
    });
    ['opt-deep', 'opt-ai', 'opt-incremental', 'opt-no-parallel'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', updateCommandPreview);
    });
}

function startScan() {
    if (!state.connected) {
        showToast('Not connected to server', 'error');
        return;
    }

    const target = document.getElementById('target-input').value.trim();
    if (!target) {
        showToast('Please enter a target domain or IP', 'error');
        document.getElementById('target-input').focus();
        return;
    }

    const params = {
        target: target,
        mode: getSelectedMode(),
        deep: document.getElementById('opt-deep').checked,
        ai: document.getElementById('opt-ai').checked,
        incremental: document.getElementById('opt-incremental').checked,
        no_parallel: document.getElementById('opt-no-parallel').checked,
        rate_limit: document.getElementById('rate-limit').value.trim() || null,
        in_scope: document.getElementById('inscope-input').value.trim() || null,
        out_of_scope: document.getElementById('outscope-input').value.trim() || null,
        output: document.getElementById('output-input').value.trim() || null,
    };

    // Clear terminal and switch to terminal view
    clearTerminal(false);
    switchView('terminal');
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelector('[data-view="terminal"]').classList.add('active');

    state.socket.emit('start_scan', params);
}

function stopScan() {
    if (state.currentScan?.pid) {
        state.socket.emit('stop_scan', { pid: state.currentScan.pid });
    }
}

function onScanStarted(data) {
    state.currentScan = data;
    state.scanStartTime = Date.now();
    state.outputLines = 0;

    // Update UI
    document.getElementById('btn-start-scan').classList.add('hidden');
    document.getElementById('btn-stop-scan').classList.remove('hidden');
    document.getElementById('scan-progress').classList.remove('hidden');
    document.getElementById('prog-target').textContent = data.target;
    document.getElementById('prog-mode').textContent = data.mode.toUpperCase();

    // Start timer
    state.scanTimer = setInterval(updateScanTimer, 1000);

    // Update status badge
    const badge = document.getElementById('global-scan-status');
    badge.className = 'scan-status-badge scanning';
    badge.innerHTML = '<span class="status-dot"></span><span>Scanning...</span>';

    // Update terminal status dot in nav
    const termDot = document.getElementById('terminal-status');
    if (termDot) { termDot.className = 'status-dot scanning'; }

    // Show scan started in terminal
    appendTerminalLine(`\x1b[36m╔════════════════════════════════════╗\x1b[0m`, true);
    appendTerminalLine(`\x1b[36m║  reconFTW Scan Started              ║\x1b[0m`, true);
    appendTerminalLine(`\x1b[36m║  Target: ${data.target.padEnd(26)}║\x1b[0m`, true);
    appendTerminalLine(`\x1b[36m║  Mode:   ${data.mode.padEnd(26)}║\x1b[0m`, true);
    appendTerminalLine(`\x1b[36m╚════════════════════════════════════╝\x1b[0m`, true);
    appendTerminalLine('', true);

    showToast(`Scan started: ${data.target}`, 'success');
}

function onScanCompleted(data) {
    clearInterval(state.scanTimer);

    const success = data.exit_code === 0;
    const msg = success ? 'Scan completed successfully!' : `Scan finished (exit code: ${data.exit_code})`;

    appendTerminalLine('', true);
    appendTerminalLine(`\x1b[${success ? '32' : '33'}m════════════════════════════════════\x1b[0m`, true);
    appendTerminalLine(`\x1b[${success ? '32' : '33'}m  ${msg}\x1b[0m`, true);
    appendTerminalLine(`\x1b[${success ? '32' : '33'}m════════════════════════════════════\x1b[0m`, true);

    showToast(msg, success ? 'success' : 'info');
    resetScanUI();
    setTimeout(loadResults, 1000);
}

function onScanStopped(data) {
    clearInterval(state.scanTimer);
    appendTerminalLine('\x1b[33m[!] Scan stopped by user\x1b[0m', true);
    showToast('Scan stopped', 'info');
    resetScanUI();
}

function resetScanUI() {
    state.currentScan = null;

    document.getElementById('btn-start-scan').classList.remove('hidden');
    document.getElementById('btn-stop-scan').classList.add('hidden');

    const badge = document.getElementById('global-scan-status');
    badge.className = 'scan-status-badge';
    badge.innerHTML = '<span class="status-dot"></span><span>Idle</span>';

    const termDot = document.getElementById('terminal-status');
    if (termDot) termDot.className = 'status-dot';
}

function updateScanTimer() {
    if (!state.scanStartTime) return;
    const elapsed = Math.floor((Date.now() - state.scanStartTime) / 1000);
    const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
    const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
    const s = (elapsed % 60).toString().padStart(2, '0');
    const el = document.getElementById('scan-timer');
    if (el) el.textContent = `${h}:${m}:${s}`;
}

function updateProgressStats() {
    const el = document.getElementById('prog-lines');
    if (el) el.textContent = state.outputLines.toLocaleString();
    const termCount = document.getElementById('term-line-count');
    if (termCount) termCount.textContent = `${state.outputLines} lines`;
}

// ============ TERMINAL ============
function initTerminal() {
    document.getElementById('btn-clear-term').addEventListener('click', () => clearTerminal(true));
    document.getElementById('btn-dl-log').addEventListener('click', downloadLog);
}

function appendTerminalLine(line, raw = false) {
    const terminal = document.getElementById('terminal-output');
    if (!terminal) return;

    // Remove welcome screen if present
    const welcome = terminal.querySelector('.terminal-welcome');
    if (welcome) welcome.remove();

    const lineEl = document.createElement('div');
    lineEl.className = 'term-line';
    lineEl.innerHTML = formatTerminalLine(line);
    terminal.appendChild(lineEl);
    state.terminalLines.push(line);

    // Auto-scroll
    if (document.getElementById('autoscroll')?.checked) {
        terminal.scrollTop = terminal.scrollHeight;
    }

    // Keep max 5000 lines
    if (state.terminalLines.length > 5000) {
        state.terminalLines.shift();
        if (terminal.children.length > 5000) {
            terminal.removeChild(terminal.children[0]);
        }
    }
}

function formatTerminalLine(line) {
    if (!line) return '<br>';

    // Strip ANSI escape codes and colorize
    let html = escapeHtml(line);

    // Basic ANSI color mapping
    html = html
        .replace(/\x1b\[0m/g, '</span>')
        .replace(/\x1b\[1m/g, '<span class="ansi-bold">')
        .replace(/\x1b\[30m/g, '<span style="color:#555">')
        .replace(/\x1b\[31m/g, '<span class="ansi-red">')
        .replace(/\x1b\[32m/g, '<span class="ansi-green">')
        .replace(/\x1b\[33m/g, '<span class="ansi-yellow">')
        .replace(/\x1b\[34m/g, '<span class="ansi-blue">')
        .replace(/\x1b\[35m/g, '<span class="ansi-magenta">')
        .replace(/\x1b\[36m/g, '<span class="ansi-cyan">')
        .replace(/\x1b\[37m/g, '<span class="ansi-white">')
        .replace(/\x1b\[1;31m/g, '<span class="ansi-red ansi-bold">')
        .replace(/\x1b\[1;32m/g, '<span class="ansi-green ansi-bold">')
        .replace(/\x1b\[1;33m/g, '<span class="ansi-yellow ansi-bold">')
        .replace(/\x1b\[1;34m/g, '<span class="ansi-blue ansi-bold">')
        .replace(/\x1b\[1;36m/g, '<span class="ansi-cyan ansi-bold">')
        .replace(/\x1b\[[0-9;]*m/g, ''); // Remove remaining codes

    // Balance spans
    const openCount = (html.match(/<span/g) || []).length;
    const closeCount = (html.match(/<\/span>/g) || []).length;
    for (let i = 0; i < openCount - closeCount; i++) html += '</span>';

    // Auto-colorize common patterns
    if (!html.includes('<span')) {
        if (line.match(/\[CRITICAL\]|CRITICAL|VULN|VULNERABLE/i)) html = `<span class="ansi-red ansi-bold">${html}</span>`;
        else if (line.match(/\[HIGH\]|high severity/i)) html = `<span style="color:#ff8a4a">${html}</span>`;
        else if (line.match(/\[ERROR\]|ERROR|FAIL/i)) html = `<span class="ansi-red">${html}</span>`;
        else if (line.match(/\[WARN\]|WARNING/i)) html = `<span class="ansi-yellow">${html}</span>`;
        else if (line.match(/\[OK\]|\[DONE\]|\[SUCCESS\]|completed|found/i)) html = `<span class="ansi-green">${html}</span>`;
        else if (line.match(/\[INFO\]|\[+\]|\[\*\]/)) html = `<span class="ansi-cyan">${html}</span>`;
    }

    return html;
}

function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function clearTerminal(keepWelcome = false) {
    const terminal = document.getElementById('terminal-output');
    terminal.innerHTML = '';
    state.terminalLines = [];
    state.outputLines = 0;

    if (keepWelcome) {
        terminal.innerHTML = `
            <div class="terminal-welcome">
                <div class="ascii-art">
                    <pre class="ascii"> ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   █████▒
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██   ▒
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒████ ░
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░</pre>
                </div>
                <p class="welcome-text">Terminal cleared. Ready for next scan.</p>
            </div>`;
    }
    updateProgressStats();
}

function downloadLog() {
    const lines = state.terminalLines.join('\n');
    const blob = new Blob([lines], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconftw-log-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Log saved!', 'success');
}

// ============ RESULTS ============
function loadResults() {
    fetch('/api/results')
        .then(r => r.json())
        .then(data => {
            state.results = data;
            renderResults();
            const badge = document.getElementById('results-count');
            if (badge) badge.textContent = data.length;
        })
        .catch(e => console.error('Failed to load results:', e));
}

function renderResults() {
    const grid = document.getElementById('results-grid');
    const empty = document.getElementById('results-empty');

    if (!state.results.length) {
        empty.style.display = 'flex';
        grid.innerHTML = '';
        return;
    }

    empty.style.display = 'none';
    grid.innerHTML = state.results.map(r => createResultCard(r)).join('');

    // Attach click handlers
    grid.querySelectorAll('.result-card').forEach((card, i) => {
        card.addEventListener('click', () => showResultDetail(state.results[i]));
    });
}

function createResultCard(r) {
    const totalVulns = Object.values(r.vulns).reduce((a, b) => a + b, 0);
    const vulnBadges = totalVulns > 0 ?
        Object.entries(r.vulns)
            .filter(([, v]) => v > 0)
            .map(([k, v]) => `<span class="vuln-badge ${k}">${k}: ${v}</span>`)
            .join('') :
        '<span class="vuln-badge none">No vulns found</span>';

    return `
        <div class="result-card">
            <div class="result-target">${escapeHtml(r.target)}</div>
            <div class="result-meta">Last modified: ${r.modified}</div>
            <div class="result-stats">
                <div class="result-stat">
                    <span class="result-stat-val cyan-val">${r.subdomains}</span>
                    <span class="result-stat-label">Subdomains</span>
                </div>
                <div class="result-stat">
                    <span class="result-stat-val blue-val">${r.webs}</span>
                    <span class="result-stat-label">Web Targets</span>
                </div>
                <div class="result-stat">
                    <span class="result-stat-val" style="color:${totalVulns > 0 ? 'var(--red)' : 'var(--green)'}">${totalVulns}</span>
                    <span class="result-stat-label">Vulns</span>
                </div>
            </div>
            <div class="vuln-badges">${vulnBadges}</div>
        </div>`;
}

function showResultDetail(result) {
    document.getElementById('results-list').classList.add('hidden');
    const detail = document.getElementById('result-detail');
    detail.classList.remove('hidden');

    document.getElementById('detail-target-name').textContent = result.target;

    // Stats bar
    const stats = document.getElementById('detail-stats');
    const totalVulns = Object.values(result.vulns).reduce((a, b) => a + b, 0);
    stats.innerHTML = `
        <div class="stats-bar-item">
            <span class="stats-bar-val" style="color:var(--cyan)">${result.subdomains}</span>
            <span class="stats-bar-label">Subdomains</span>
        </div>
        <div class="stats-bar-item">
            <span class="stats-bar-val" style="color:var(--blue)">${result.webs}</span>
            <span class="stats-bar-label">Web Targets</span>
        </div>
        <div class="stats-bar-item">
            <span class="stats-bar-val" style="color:var(--red)">${result.vulns.critical}</span>
            <span class="stats-bar-label">Critical</span>
        </div>
        <div class="stats-bar-item">
            <span class="stats-bar-val" style="color:var(--orange)">${result.vulns.high}</span>
            <span class="stats-bar-label">High</span>
        </div>
        <div class="stats-bar-item">
            <span class="stats-bar-val" style="color:var(--yellow)">${result.vulns.medium}</span>
            <span class="stats-bar-label">Medium</span>
        </div>`;

    // Load detailed results
    fetch(`/api/results/${encodeURIComponent(result.target)}`)
        .then(r => r.json())
        .then(data => renderDetailTabs(data))
        .catch(e => console.error(e));
}

function renderDetailTabs(data) {
    const tabNav = document.getElementById('result-tab-nav');
    const tabContent = document.getElementById('result-tab-content');

    const tabDefs = [
        { key: 'subdomains', label: '🌐 Subdomains', color: 'var(--cyan)' },
        { key: 'webs', label: '🔗 Web Targets', color: 'var(--blue)' },
        { key: 'vulns_critical', label: '🔴 Critical', color: 'var(--red)' },
        { key: 'vulns_high', label: '🟠 High', color: 'var(--orange)' },
        { key: 'vulns_medium', label: '🟡 Medium', color: 'var(--yellow)' },
        { key: 'vulns_low', label: '🟢 Low', color: 'var(--green)' },
        { key: 'vulns_info', label: '🔵 Info', color: 'var(--blue)' },
        { key: 'emails', label: '📧 Emails', color: 'var(--purple)' },
        { key: 'ports', label: '🔌 Ports', color: 'var(--orange)' },
        { key: 'js_files', label: '📜 JS Files', color: 'var(--yellow)' },
        { key: 'gf_sqli', label: '💉 SQLi', color: 'var(--red)' },
        { key: 'gf_xss', label: '⚡ XSS', color: 'var(--orange)' },
        { key: 'google_dorks', label: '🔍 G-Dorks', color: 'var(--cyan)' },
        { key: 'technologies', label: '⚙️ Tech', color: 'var(--text-secondary)' },
    ];

    const availableTabs = tabDefs.filter(t => data.files && data.files[t.key]);

    if (!availableTabs.length) {
        tabNav.innerHTML = '';
        tabContent.innerHTML = '<div class="empty-state"><p>No result files found yet. The scan may still be running.</p></div>';
        return;
    }

    tabNav.innerHTML = availableTabs.map((t, i) => {
        const count = data.files[t.key]?.total || 0;
        return `<button class="tab-btn ${i === 0 ? 'active' : ''}" data-tab="${t.key}">${t.label} <span style="color:${t.color};font-size:10px">${count}</span></button>`;
    }).join('');

    tabContent.innerHTML = availableTabs.map((t, i) => {
        const fileData = data.files[t.key];
        const lines = fileData.lines.map(l => `<span class="result-file-line">${escapeHtml(l)}</span>`).join('');
        const truncNote = fileData.total > 200 ? `<span style="color:var(--yellow);font-size:11px"> (showing first 200 of ${fileData.total})</span>` : '';
        return `
            <div class="tab-pane ${i === 0 ? 'active' : ''}" id="tab-${t.key}">
                <div class="result-file">
                    <div class="result-file-header">
                        <span>${fileData.path}</span>
                        <span>${fileData.total} entries${truncNote}</span>
                    </div>
                    <div class="result-file-body">${lines || '<span style="color:var(--text-muted)">Empty file</span>'}</div>
                </div>
            </div>`;
    }).join('');

    // Tab switching
    tabNav.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            tabNav.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            tabContent.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const pane = document.getElementById(`tab-${btn.dataset.tab}`);
            if (pane) pane.classList.add('active');
        });
    });
}

function initResultsActions() {
    document.getElementById('btn-back-results').addEventListener('click', () => {
        document.getElementById('results-list').classList.remove('hidden');
        document.getElementById('result-detail').classList.add('hidden');
    });

    document.getElementById('btn-refresh-results').addEventListener('click', () => {
        loadResults();
        showToast('Results refreshed', 'info');
    });
}

// ============ CONFIG ============
function loadConfig() {
    fetch('/api/config')
        .then(r => r.json())
        .then(data => {
            const editor = document.getElementById('config-editor');
            if (editor) {
                editor.value = data.config;
                state.configOriginal = data.config;
            }
            renderQuickConfig(data.config);
        })
        .catch(e => console.error('Failed to load config:', e));
}

function renderQuickConfig(cfgText) {
    const quickParams = [
        { key: 'OSINT', label: 'OSINT' },
        { key: 'SUBDOMAINS_GENERAL', label: 'Subdomains' },
        { key: 'VULNS_GENERAL', label: 'Vulns Scan' },
        { key: 'NUCLEICHECK', label: 'Nuclei' },
        { key: 'DEEP', label: 'Deep Mode' },
        { key: 'WEBSCREENSHOT', label: 'Screenshots' },
        { key: 'SUBBRUTE', label: 'DNS Brute' },
        { key: 'SUBPERMUTE', label: 'Permutations' },
        { key: 'FUZZ', label: 'Web Fuzzing' },
        { key: 'JSCHECKS', label: 'JS Analysis' },
        { key: 'PORTSCANNER', label: 'Port Scanner' },
        { key: 'CLOUD_ENUM', label: 'Cloud Enum' },
        { key: 'GITHUB_DORKS', label: 'GitHub Dorks' },
        { key: 'GOOGLE_DORKS', label: 'Google Dorks' },
        { key: 'XSS', label: 'XSS Check' },
        { key: 'SQLI', label: 'SQLi Check' },
        { key: 'SSRF_CHECKS', label: 'SSRF Check' },
        { key: 'LFI', label: 'LFI Check' },
        { key: 'NOTIFICATION', label: 'Notifications' },
        { key: 'PARALLEL_MODE', label: 'Parallel Mode' },
    ];

    const grid = document.getElementById('quick-config-grid');
    grid.innerHTML = quickParams.map(p => {
        const match = cfgText.match(new RegExp(`^${p.key}=(true|false)`, 'm'));
        const isOn = match && match[1] === 'true';
        return `
            <label class="quick-toggle" data-key="${p.key}">
                <input type="checkbox" ${isOn ? 'checked' : ''}>
                <div class="quick-toggle-slider"></div>
                <span class="quick-toggle-label">${p.label}</span>
            </label>`;
    }).join('');

    // Sync toggles to textarea
    grid.querySelectorAll('.quick-toggle input').forEach(input => {
        input.addEventListener('change', () => {
            const key = input.closest('.quick-toggle').dataset.key;
            const val = input.checked ? 'true' : 'false';
            const editor = document.getElementById('config-editor');
            editor.value = editor.value.replace(
                new RegExp(`^(${key}=)(true|false)`, 'm'),
                `$1${val}`
            );
        });
    });
}

function initConfigActions() {
    document.getElementById('btn-save-cfg').addEventListener('click', () => {
        const config = document.getElementById('config-editor').value;
        fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) showToast('Configuration saved!', 'success');
            else showToast('Error: ' + data.error, 'error');
        });
    });

    document.getElementById('btn-reset-cfg').addEventListener('click', () => {
        if (confirm('Reset configuration to last saved version?')) {
            const editor = document.getElementById('config-editor');
            editor.value = state.configOriginal;
            loadConfig();
            showToast('Configuration reset', 'info');
        }
    });
}

// ============ TOOLS CHECK ============
function checkTools() {
    const grid = document.getElementById('tools-grid');
    grid.innerHTML = '<div class="loading-spinner"><div class="spinner"></div><span>Checking tools...</span></div>';

    fetch('/api/tools/check')
        .then(r => r.json())
        .then(data => {
            const installed = Object.values(data).filter(v => v).length;
            const total = Object.keys(data).length;

            grid.innerHTML = `
                <div style="grid-column:1/-1; margin-bottom:12px; color:var(--text-secondary); font-size:12px">
                    <span style="color:var(--green)">${installed}</span> / ${total} tools installed
                </div>` +
                Object.entries(data).map(([tool, ok]) => `
                    <div class="tool-item">
                        <div class="tool-status-dot ${ok ? 'installed' : 'missing'}"></div>
                        <span class="tool-name">${escapeHtml(tool)}</span>
                        <span class="tool-status-text ${ok ? 'ok' : 'missing'}">${ok ? '✓' : '✗'}</span>
                    </div>`).join('');
        })
        .catch(() => {
            grid.innerHTML = '<div style="color:var(--red);padding:20px">Failed to check tools</div>';
        });

    document.getElementById('btn-check-tools').addEventListener('click', () => checkTools(), { once: true });
}

// ============ TOAST ============
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const icons = {
        success: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
        error: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        info: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `${icons[type] || icons.info}<span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => toast.remove(), 3200);
}

// ============ INIT ============
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    initNavigation();
    initModeSelection();
    initScanActions();
    initTerminal();
    initResultsActions();
    initConfigActions();
    updateCommandPreview();

    // Load results count on start
    setTimeout(loadResults, 1000);
});
