/* ═══════════════════════════════════════════════════════════
   reconFTW WebUI — Full App with Live Monitoring & Themes
   ═══════════════════════════════════════════════════════════ */
'use strict';

/* ─── PARTICLE CANVAS BACKGROUND ─── */
function initParticles() {
  const canvas = document.getElementById('bgCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const count = window.innerWidth < 768 ? 30 : 60;
  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * 1920, y: Math.random() * 1080,
      r: Math.random() * 1.5 + 0.3,
      vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
      a: Math.random()
    });
  }

  function getAccentRgb() {
    const el = document.documentElement;
    const v = getComputedStyle(el).getPropertyValue('--accent').trim();
    // extract rgb from hex or named
    const d = document.createElement('div');
    d.style.color = v; document.body.appendChild(d);
    const c = getComputedStyle(d).color; document.body.removeChild(d);
    const m = c.match(/\d+/g);
    return m ? [+m[0], +m[1], +m[2]] : [0, 212, 255];
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    const [r, g, b] = getAccentRgb();
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      p.a += 0.005;
      const alpha = (Math.sin(p.a) * 0.5 + 0.5) * 0.4 + 0.1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${r},${g},${b},${alpha})`;
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
}

/* ─── STATE ─── */
const S = {
  socket: null, connected: false,
  currentScan: null, scanStart: null, timerInterval: null,
  outputLines: 0, termLines: [],
  results: [], configOriginal: '',
  currentView: 'scanner',
  liveSubs: 0, liveWebs: 0, liveVulns: 0,
  modules: {},
  modeManuallySet: false,   // true once user clicks a mode card
};

/* ─── SCAN MODULE PATTERNS ─── */
const MODULE_PATTERNS = [
  { key: 'osint',       label: 'OSINT',            re: /osint|google.dork|github|email|whois/i },
  { key: 'subdomains',  label: 'Subdomains',        re: /subfinder|amass|subdomains|enumerat|crtsh|brute/i },
  { key: 'dns',         label: 'DNS Resolution',    re: /dnsx|puredns|resolv|massdns/i },
  { key: 'web_probe',   label: 'Web Probing',        re: /httpx|web.prob|screensho|gowitness/i },
  { key: 'portscan',    label: 'Port Scanner',       re: /nmap|naabu|portscan|port.scan/i },
  { key: 'crawl',       label: 'Crawling & Fuzzing', re: /katana|hakrawler|ffuf|fuzz|crawl/i },
  { key: 'js',          label: 'JS Analysis',        re: /javascript|js.file|getjswords|linkfinder/i },
  { key: 'nuclei',      label: 'Nuclei Scan',        re: /nuclei|template/i },
  { key: 'vulns',       label: 'Vulnerability Scan', re: /dalfox|sqlmap|xss|sqli|ssrf|lfi|ssti/i },
  { key: 'report',      label: 'Report Generation',  re: /report|summary|finaliz|hotlist/i },
];

/* ─── SOCKET.IO ─── */
function initSocket() {
  S.socket = io({ transports: ['websocket', 'polling'] });

  S.socket.on('connect', () => {
    S.connected = true;
    setConnStatus(true);
    toast('Connected to reconFTW server', 'success');
    loadResults();
  });
  S.socket.on('disconnect', () => {
    S.connected = false;
    setConnStatus(false);
    toast('Disconnected from server', 'error');
  });
  S.socket.on('connected', () => {});
  S.socket.on('scan_started',   onScanStarted);
  S.socket.on('scan_pid',       d => { if (S.currentScan) S.currentScan.pid = d.pid; });
  S.socket.on('scan_output',    onScanOutput);
  S.socket.on('scan_completed', onScanCompleted);
  S.socket.on('scan_stopped',   onScanStopped);
  S.socket.on('scan_error',     d => { toast(d.message, 'error'); resetScanUI(); });
}

/* ─── CONNECTION ─── */
function setConnStatus(on) {
  const dot = document.getElementById('connDot');
  const lbl = document.getElementById('connLabel');
  if (dot) dot.className = 'conn-dot ' + (on ? 'on' : 'err');
  if (lbl) lbl.textContent = on ? 'Connected' : 'Offline';
}

/* ─── NAVIGATION ─── */
function initNav() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const v = link.dataset.view;
      switchView(v);
      document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      closeSidebar();
    });
  });
}

function switchView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = document.getElementById('view-' + name);
  if (el) { el.classList.add('active'); S.currentView = name; }
  if (name === 'results')  loadResults();
  if (name === 'config')   loadConfig();
  if (name === 'tools')    checkTools();
  if (name === 'settings') loadSettings();
  if (name === 'live')     updateLiveModuleList();
}

/* ─── MOBILE SIDEBAR ─── */
function initMobileNav() {
  const ham    = document.getElementById('hamburger');
  const sb     = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const sbClose = document.getElementById('sbClose');

  ham?.addEventListener('click', () => { ham.classList.toggle('open'); openSidebar(); });
  overlay?.addEventListener('click', closeSidebar);
  sbClose?.addEventListener('click', closeSidebar);
}

function openSidebar() {
  document.getElementById('sidebar')?.classList.add('open');
  document.getElementById('sidebarOverlay')?.classList.add('open');
}
function closeSidebar() {
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebarOverlay')?.classList.remove('open');
  document.getElementById('hamburger')?.classList.remove('open');
}

/* ─── THEME ─── */
function initThemes() {
  const saved = localStorage.getItem('rfwTheme') || 'cyber';
  applyTheme(saved);

  document.querySelectorAll('.tdot').forEach(btn => {
    btn.addEventListener('click', () => {
      const th = btn.dataset.theme;
      applyTheme(th);
      localStorage.setItem('rfwTheme', th);
    });
  });
}

function applyTheme(name) {
  document.documentElement.setAttribute('data-theme', name);
  document.querySelectorAll('.tdot').forEach(b => b.classList.toggle('active', b.dataset.theme === name));
}

/* ─── COMMAND PREVIEW ─── */
function updateCmd() {
  const t    = q('#inp-target')?.value.trim() || '<target>';
  const mode = getMode();
  const deep = q('#opt-deep input')?.checked;
  const ai   = q('#opt-ai input')?.checked;
  const incr = q('#opt-incr input')?.checked;
  const nopar= q('#opt-nopar input')?.checked;
  const rate = q('#inp-rate')?.value.trim();
  const ins  = q('#inp-inscope')?.value.trim();
  const outs = q('#inp-outscope')?.value.trim();
  const out  = q('#inp-output')?.value.trim();

  const mf = {recon:'-r',all:'-a',passive:'-p',subdomains:'-s',web:'-w',osint:'-n',zen:'-z'};
  let cmd = `./reconftw.sh -d ${t} ${mf[mode]||'-r'}`;
  if (deep)  cmd += ' --deep';
  if (ai)    cmd += ' --ai';
  if (incr)  cmd += ' --incremental';
  if (nopar) cmd += ' --no-parallel';
  if (rate)  cmd += ` -q ${rate}`;
  if (ins)   cmd += ` -i ${ins}`;
  if (outs)  cmd += ` -x ${outs}`;
  if (out)   cmd += ` -o ${out}`;

  const el = document.getElementById('cmdText');
  if (el) el.textContent = cmd;
}

function getMode() {
  return document.querySelector('input[name="mode"]:checked')?.value || 'recon';
}

/* ─── MODE SELECTION ─── */
function initModes() {
  document.querySelectorAll('.mode-card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('sel'));
      card.classList.add('sel');
      card.querySelector('input').checked = true;
      S.modeManuallySet = true;   // user explicitly chose a mode → stop auto-fill
      updateCmd();
    });
  });
}

/* ─── SCAN ACTIONS ─── */
function initScanActions() {
  document.getElementById('btnLaunch')?.addEventListener('click', startScan);
  document.getElementById('btnStop')?.addEventListener('click', stopScan);
  document.getElementById('btnCopy')?.addEventListener('click', () => {
    const t = document.getElementById('cmdText')?.textContent;
    navigator.clipboard?.writeText(t).then(() => toast('Command copied!', 'info'));
  });

  ['inp-target','inp-inscope','inp-outscope','inp-output','inp-rate'].forEach(id => {
    q('#'+id)?.addEventListener('input', updateCmd);
  });
  q('#inp-target')?.addEventListener('input', autoFillMode);
  document.querySelectorAll('.opt-toggle input, input[name="mode"]').forEach(el => {
    el.addEventListener('change', updateCmd);
  });
}

function startScan() {
  if (!S.connected) { toast('Not connected to server', 'error'); return; }
  const target = q('#inp-target')?.value.trim();
  if (!target) { toast('Please enter a target domain or IP', 'error'); q('#inp-target')?.focus(); return; }

  const params = {
    target,
    mode:       getMode(),
    deep:       q('#opt-deep input')?.checked,
    ai:         q('#opt-ai input')?.checked,
    incremental:q('#opt-incr input')?.checked,
    no_parallel:q('#opt-nopar input')?.checked,
    rate_limit: q('#inp-rate')?.value.trim() || null,
    in_scope:   q('#inp-inscope')?.value.trim() || null,
    out_of_scope:q('#inp-outscope')?.value.trim() || null,
    output:     q('#inp-output')?.value.trim() || null,
  };

  clearTerminal(false);
  resetLiveCounters();
  initLiveModules();
  S.socket.emit('start_scan', params);
}

function stopScan() {
  if (S.currentScan?.pid) S.socket.emit('stop_scan', { pid: S.currentScan.pid });
}

/* ─── SCAN EVENTS ─── */
function onScanStarted(data) {
  S.currentScan = { ...data, pid: null };
  S.scanStart   = Date.now();
  S.outputLines = 0;
  S.liveSubs = S.liveWebs = S.liveVulns = 0;

  // Buttons
  q('#btnLaunch')?.classList.add('hidden');
  q('#btnStop')?.classList.remove('hidden');

  // Status
  const st = document.getElementById('globalStatus');
  if (st) { st.className = 'pg-status scanning'; st.querySelector('.status-label').textContent = 'Scanning...'; }

  // Topbar
  const pill = document.getElementById('topbarPill');
  if (pill) { pill.textContent = '● Scanning'; pill.classList.add('on'); }

  // Nav pulse
  document.getElementById('scanPulse')?.classList.add('on');
  document.getElementById('liveCount').textContent = '1';

  // Timer
  S.timerInterval = setInterval(tickTimer, 1000);

  // Live banner
  const banner = document.getElementById('liveBanner');
  if (banner) banner.classList.add('scanning');
  setText('lbStateText', 'SCANNING');
  setText('lbTarget', data.target);
  setText('lbMode', data.mode.toUpperCase());

  // Switch to live
  switchView('live');
  document.querySelectorAll('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.view === 'live'));

  appendTermLine(`\x1b[36m╔═══════════════════════════════════╗`, true);
  appendTermLine(`\x1b[36m║  reconFTW Scan Started            ║`, true);
  appendTermLine(`\x1b[36m║  Target: ${data.target.substring(0,26).padEnd(26)}║`, true);
  appendTermLine(`\x1b[36m║  Mode:   ${data.mode.substring(0,26).padEnd(26)}║`, true);
  appendTermLine(`\x1b[36m╚═══════════════════════════════════╝`, true);
  appendTermLine('', true);

  toast(`Scan started: ${data.target}`, 'success');
}

function onScanOutput(data) {
  const line = data.line;
  S.outputLines++;
  appendTermLine(line);

  // Live counters from file parsing
  if (line.match(/\[subfinder\]|\[amass\]|subdomain.found|new.subdomain/i)) bump('subs');
  if (line.match(/httpx|web.target|https?:\/\//i) && !line.match(/downloading|install/i)) bump('webs');
  if (line.match(/\[critical\]|\[high\]|\[medium\]|\[low\]|vulnerability|CVE-/i)) bump('vulns');

  // Module detection
  MODULE_PATTERNS.forEach(m => {
    if (line.match(m.re)) activateModule(m.key);
  });

  // Event feed
  const type = classifyLine(line);
  if (type) addFeedItem(line, type);

  // Update counters
  setText('cnt-lines', S.outputLines.toLocaleString());
  setText('termLinesCount', `${S.outputLines} lines`);
  animateBar('bar-lines', Math.min((S.outputLines / 2000) * 100, 100));
}

function bump(key) {
  if (key === 'subs')  { S.liveSubs++;  animateLcNum('cnt-subs',  S.liveSubs);  animateBar('bar-subs',  Math.min(S.liveSubs/500*100,100)); }
  if (key === 'webs')  { S.liveWebs++;  animateLcNum('cnt-webs',  S.liveWebs);  animateBar('bar-webs',  Math.min(S.liveWebs/200*100,100)); }
  if (key === 'vulns') { S.liveVulns++; animateLcNum('cnt-vulns', S.liveVulns); animateBar('bar-vulns', Math.min(S.liveVulns/50*100,100)); }
}

function animateLcNum(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = val.toLocaleString();
  el.style.transform = 'scale(1.15)';
  setTimeout(() => { el.style.transform = 'scale(1)'; }, 200);
}

function animateBar(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = pct + '%';
}

function onScanCompleted(data) {
  clearInterval(S.timerInterval);
  const ok = data.exit_code === 0;
  appendTermLine('', true);
  appendTermLine(`\x1b[${ok?'32':'33'}m════ Scan ${ok?'Completed':'Finished'} (exit: ${data.exit_code}) ════`, true);

  // Update modules
  Object.keys(S.modules).forEach(k => {
    if (S.modules[k].status === 'running') setModuleStatus(k, 'done');
  });
  setModuleStatus('report', 'done');

  const st = document.getElementById('globalStatus');
  if (st) { st.className = 'pg-status done'; st.querySelector('.status-label').textContent = 'Completed'; }

  // banner
  document.getElementById('liveBanner')?.classList.remove('scanning');
  setText('lbStateText', ok ? 'Scan Complete' : 'Finished');

  toast(ok ? 'Scan completed!' : `Scan done (exit: ${data.exit_code})`, ok ? 'success' : 'info');
  resetScanUI(false);
  setTimeout(loadResults, 1200);
}

function onScanStopped() {
  clearInterval(S.timerInterval);
  appendTermLine('\x1b[33m[!] Scan stopped by user', true);
  document.getElementById('liveBanner')?.classList.remove('scanning');
  setText('lbStateText', 'Stopped');
  toast('Scan stopped', 'info');
  resetScanUI(false);
}

function resetScanUI(clearAll = true) {
  S.currentScan = null;
  q('#btnLaunch')?.classList.remove('hidden');
  q('#btnStop')?.classList.add('hidden');
  document.getElementById('scanPulse')?.classList.remove('on');
  document.getElementById('liveCount').textContent = '0';
  const pill = document.getElementById('topbarPill');
  if (pill) { pill.textContent = ''; pill.classList.remove('on'); }
  const st = document.getElementById('globalStatus');
  if (st && clearAll) { st.className = 'pg-status'; st.querySelector('.status-label').textContent = 'Ready'; }
}

/* ─── TIMER ─── */
function tickTimer() {
  if (!S.scanStart) return;
  const e = Math.floor((Date.now() - S.scanStart) / 1000);
  const h = String(Math.floor(e/3600)).padStart(2,'0');
  const m = String(Math.floor((e%3600)/60)).padStart(2,'0');
  const s = String(e%60).padStart(2,'0');
  setText('lbTimer', `${h}:${m}:${s}`);
}

/* ─── LIVE MODULES ─── */
function initLiveModules() {
  S.modules = {};
  MODULE_PATTERNS.forEach(m => { S.modules[m.key] = { status: 'pending', label: m.label }; });
  updateLiveModuleList();
}

function activateModule(key) {
  if (!S.modules[key]) return;
  // mark all prior as done
  let found = false;
  MODULE_PATTERNS.forEach(m => {
    if (m.key === key) found = true;
    if (!found && S.modules[m.key]?.status === 'running') setModuleStatus(m.key, 'done');
  });
  if (S.modules[key].status !== 'done') setModuleStatus(key, 'running');
}

function setModuleStatus(key, status) {
  if (!S.modules[key]) return;
  S.modules[key].status = status;
  updateLiveModuleList();
}

function updateLiveModuleList() {
  const list = document.getElementById('modulesList');
  if (!list) return;
  if (!Object.keys(S.modules).length) {
    list.innerHTML = `<div class="feed-empty">Start a scan to see module progress</div>`;
    return;
  }
  list.innerHTML = MODULE_PATTERNS.map(m => {
    const mod = S.modules[m.key] || { status: 'pending' };
    const icons = { pending: '○', running: '◉', done: '✓', err: '✗' };
    const st = mod.status || 'pending';
    return `<div class="mod-item ${st}">
      <div class="mod-dot ${st==='running'?'running':st==='done'?'done':st==='err'?'err':''}"></div>
      <div class="mod-name">${m.label}</div>
      <div class="mod-status">${st.toUpperCase()}</div>
    </div>`;
  }).join('');
}

function resetLiveCounters() {
  S.liveSubs = S.liveWebs = S.liveVulns = 0;
  ['cnt-subs','cnt-webs','cnt-vulns','cnt-lines'].forEach(id => setText(id, '0'));
  ['bar-subs','bar-webs','bar-vulns','bar-lines'].forEach(id => animateBar(id, 0));
  setText('lbTimer', '00:00:00');
}

/* ─── EVENT FEED ─── */
function classifyLine(line) {
  const l = line.toLowerCase();
  if (l.match(/critical|cve-|vulnerab|exploit/)) return 'vuln';
  if (l.match(/\[+\]|done|found|success|complet/)) return 'success';
  if (l.match(/error|fail|exception/)) return 'err';
  if (l.match(/warning|warn/)) return 'warn';
  if (l.match(/\[\*\]|\[~\]|running|start|launch/)) return 'info';
  return null;
}

function addFeedItem(line, type) {
  const feed = document.getElementById('eventFeed');
  if (!feed) return;
  const empty = feed.querySelector('.feed-empty');
  if (empty) empty.remove();

  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
  const clean = stripAnsi(line).substring(0, 120);

  const item = document.createElement('div');
  item.className = 'feed-item';
  item.innerHTML = `<span class="feed-time">${ts}</span><span class="feed-type ${type}">${type.toUpperCase()}</span><span class="feed-text ${type==='vuln'||type==='success'?'highlight':''}">${esc(clean)}</span>`;
  feed.appendChild(item);

  // Max 150 items
  while (feed.children.length > 150) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

document.getElementById('btnClearFeed')?.addEventListener('click', () => {
  const feed = document.getElementById('eventFeed');
  if (feed) feed.innerHTML = '<div class="feed-empty">Feed cleared.</div>';
});

/* ─── TERMINAL ─── */
function initTerminal() {
  document.getElementById('btnClearTerm')?.addEventListener('click', () => clearTerminal(true));
  document.getElementById('btnDlLog')?.addEventListener('click', downloadLog);
}

function appendTermLine(line, raw = false) {
  const term = document.getElementById('terminal');
  if (!term) return;
  const splash = term.querySelector('.term-splash');
  if (splash) splash.remove();

  const el = document.createElement('span');
  el.className = 'tl';
  el.innerHTML = ansiToHtml(line) || '<br>';
  term.appendChild(el);
  S.termLines.push(line);

  if (document.getElementById('autoScroll')?.checked) term.scrollTop = term.scrollHeight;
  if (S.termLines.length > 6000) { S.termLines.shift(); if (term.children.length > 6000) term.removeChild(term.firstChild); }
}

function clearTerminal(splash = true) {
  const term = document.getElementById('terminal');
  if (!term) return;
  term.innerHTML = '';
  S.termLines = [];
  if (splash) term.innerHTML = `<div class="term-splash" id="termSplash"><p style="color:var(--text2)">Terminal cleared.</p></div>`;
  setText('termLinesCount', '0 lines');
}

function downloadLog() {
  const blob = new Blob([S.termLines.map(stripAnsi).join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url;
  a.download = `reconftw-${Date.now()}.log`; a.click();
  URL.revokeObjectURL(url);
  toast('Log saved!', 'success');
}

/* ─── ANSI → HTML ─── */
function ansiToHtml(text) {
  if (!text) return '';
  let h = esc(text);
  h = h
    .replace(/\x1b\[0m/g,       '</span>')
    .replace(/\x1b\[1m/g,       '<span class="abold">')
    .replace(/\x1b\[31m/g,      '<span class="ar">')
    .replace(/\x1b\[32m/g,      '<span class="ag">')
    .replace(/\x1b\[33m/g,      '<span class="ay">')
    .replace(/\x1b\[34m/g,      '<span class="ab">')
    .replace(/\x1b\[35m/g,      '<span class="am">')
    .replace(/\x1b\[36m/g,      '<span class="ac">')
    .replace(/\x1b\[37m/g,      '<span class="aw">')
    .replace(/\x1b\[1;31m/g,    '<span class="ar abold">')
    .replace(/\x1b\[1;32m/g,    '<span class="ag abold">')
    .replace(/\x1b\[1;33m/g,    '<span class="ay abold">')
    .replace(/\x1b\[1;36m/g,    '<span class="ac abold">')
    .replace(/\x1b\[[0-9;]+m/g, '');
  const opens = (h.match(/<span/g) || []).length;
  const closes = (h.match(/<\/span>/g) || []).length;
  for (let i = 0; i < opens - closes; i++) h += '</span>';
  return h;
}

function stripAnsi(s) { return (s||'').replace(/\x1b\[[0-9;]*m/g, ''); }

/* ─── RESULTS ─── */
function loadResults() {
  fetch('/api/results')
    .then(r => r.json())
    .then(data => {
      S.results = data;
      renderResults();
      const n = data.length;
      setText('resultsBadge', n);
    })
    .catch(() => {});
}

function renderResults() {
  const grid = document.getElementById('resultsGrid');
  const empty = document.getElementById('resultsEmpty');
  if (!grid) return;
  if (!S.results.length) { if (empty) empty.style.display = 'flex'; grid.innerHTML = ''; return; }
  if (empty) empty.style.display = 'none';
  grid.innerHTML = S.results.map((r, i) => buildResultCard(r, i)).join('');
  grid.querySelectorAll('.rc').forEach((c, i) => c.addEventListener('click', () => showResultDetail(S.results[i])));
}

function buildResultCard(r, i) {
  const tv = Object.values(r.vulns).reduce((a, b) => a + b, 0);
  const badges = tv > 0
    ? Object.entries(r.vulns).filter(([,v]) => v > 0)
        .map(([k,v]) => `<span class="vb ${k}">${k[0].toUpperCase()+k.slice(1)}: ${v}</span>`).join('')
    : '<span class="vb none">Clean</span>';
  return `<div class="rc" data-i="${i}">
    <div class="rc-host">${esc(r.target)}</div>
    <div class="rc-date">${r.modified}</div>
    <div class="rc-stats">
      <div class="rcs"><span class="rcs-val" style="color:var(--accent)">${r.subdomains}</span><span class="rcs-key">Subs</span></div>
      <div class="rcs"><span class="rcs-val" style="color:var(--blue)">${r.webs}</span><span class="rcs-key">Webs</span></div>
      <div class="rcs"><span class="rcs-val" style="color:${tv>0?'var(--hot)':'var(--green)'}">${tv}</span><span class="rcs-key">Vulns</span></div>
    </div>
    <div class="vbadges">${badges}</div>
  </div>`;
}

function showResultDetail(r) {
  document.getElementById('resultsListWrap').classList.add('hidden');
  const det = document.getElementById('resultDetail');
  det.classList.remove('hidden');
  setText('rdTitle', r.target);

  const tv = Object.values(r.vulns).reduce((a, b) => a + b, 0);
  document.getElementById('rdStats').innerHTML = [
    ['Subdomains', r.subdomains, 'var(--accent)'],
    ['Web Targets', r.webs, 'var(--blue)'],
    ['Critical', r.vulns.critical, 'var(--hot)'],
    ['High', r.vulns.high, 'var(--warm)'],
    ['Medium', r.vulns.medium, 'var(--yellow)'],
    ['Total Vulns', tv, tv > 0 ? 'var(--hot)' : 'var(--green)'],
  ].map(([k,v,c]) => `<div class="rds"><span class="rds-val" style="color:${c}">${v}</span><span class="rds-key">${k}</span></div>`).join('');

  fetch(`/api/results/${encodeURIComponent(r.target)}`).then(res => res.json()).then(buildDetailTabs).catch(console.error);
}

function buildDetailTabs(data) {
  const defs = [
    { k:'subdomains',   lbl:'🌐 Subdomains',   col:'var(--accent)' },
    { k:'webs',         lbl:'🔗 Webs',          col:'var(--blue)' },
    { k:'vulns_critical',lbl:'🔴 Critical',     col:'var(--hot)' },
    { k:'vulns_high',   lbl:'🟠 High',          col:'var(--warm)' },
    { k:'vulns_medium', lbl:'🟡 Medium',        col:'var(--yellow)' },
    { k:'vulns_low',    lbl:'🟢 Low',           col:'var(--green)' },
    { k:'vulns_info',   lbl:'🔵 Info',          col:'var(--blue)' },
    { k:'emails',       lbl:'📧 Emails',        col:'var(--purple)' },
    { k:'ports',        lbl:'🔌 Ports',         col:'var(--warm)' },
    { k:'js_files',     lbl:'📜 JS',            col:'var(--yellow)' },
    { k:'gf_sqli',      lbl:'💉 SQLi',          col:'var(--hot)' },
    { k:'gf_xss',       lbl:'⚡ XSS',           col:'var(--warm)' },
    { k:'google_dorks', lbl:'🔍 G-Dorks',       col:'var(--accent)' },
    { k:'technologies', lbl:'⚙️ Tech',          col:'var(--text2)' },
  ];
  const avail = defs.filter(d => data.files?.[d.k]);
  if (!avail.length) { document.getElementById('rdTabNav').innerHTML = ''; document.getElementById('rdTabBody').innerHTML = '<div class="feed-empty">No result files found yet.</div>'; return; }

  document.getElementById('rdTabNav').innerHTML = avail.map((d, i) => {
    const tot = data.files[d.k]?.total || 0;
    return `<button class="tbn ${i===0?'active':''}" data-tab="${d.k}">${d.lbl} <span style="color:${d.col};font-size:10px">${tot}</span></button>`;
  }).join('');

  document.getElementById('rdTabBody').innerHTML = avail.map((d, i) => {
    const fd = data.files[d.k];
    const lines = fd.lines.map(l => `<span class="rf-line">${esc(l)}</span>`).join('');
    const note = fd.total > 200 ? ` <span style="color:var(--yellow)">(first 200 of ${fd.total})</span>` : '';
    return `<div class="tp ${i===0?'active':''}" id="tp-${d.k}">
      <div class="rf-wrap">
        <div class="rf-head"><span>${fd.path}</span><span>${fd.total} entries${note}</span></div>
        <div class="rf-body">${lines || '<span style="color:var(--muted)">Empty</span>'}</div>
      </div>
    </div>`;
  }).join('');

  document.getElementById('rdTabNav').querySelectorAll('.tbn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tbn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tp').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tp-' + btn.dataset.tab)?.classList.add('active');
    });
  });
}

function initResultsActions() {
  document.getElementById('btnBackResults')?.addEventListener('click', () => {
    document.getElementById('resultsListWrap').classList.remove('hidden');
    document.getElementById('resultDetail').classList.add('hidden');
  });
  document.getElementById('btnRefreshResults')?.addEventListener('click', () => { loadResults(); toast('Refreshed','info'); });
}

/* ─── CONFIG ─── */
function loadConfig() {
  fetch('/api/config').then(r => r.json()).then(d => {
    const ed = document.getElementById('cfgEditor');
    if (ed) { ed.value = d.config; S.configOriginal = d.config; }
    buildQuickToggles(d.config);
  }).catch(() => {});
}

function buildQuickToggles(cfg) {
  const params = [
    'OSINT','SUBDOMAINS_GENERAL','VULNS_GENERAL','NUCLEICHECK','DEEP',
    'WEBSCREENSHOT','SUBBRUTE','SUBPERMUTE','FUZZ','JSCHECKS',
    'PORTSCANNER','CLOUD_ENUM','GITHUB_DORKS','GOOGLE_DORKS',
    'XSS','SQLI','SSRF_CHECKS','LFI','PARALLEL_MODE','NOTIFICATION',
  ];
  const grid = document.getElementById('qTogGrid');
  if (!grid) return;
  grid.innerHTML = params.map(p => {
    const m = cfg.match(new RegExp(`^${p}=(true|false)`, 'm'));
    const on = m && m[1] === 'true';
    return `<label class="qtog" data-key="${p}">
      <input type="checkbox" ${on ? 'checked' : ''}>
      <div class="qtog-slider"></div>
      <span class="qtog-name">${p.replace(/_/g,' ')}</span>
    </label>`;
  }).join('');
  grid.querySelectorAll('.qtog input').forEach(inp => {
    inp.addEventListener('change', () => {
      const key = inp.closest('.qtog').dataset.key;
      const val = inp.checked ? 'true' : 'false';
      const ed = document.getElementById('cfgEditor');
      if (ed) ed.value = ed.value.replace(new RegExp(`^(${key}=)(true|false)`, 'm'), `$1${val}`);
    });
  });
}

function initConfigActions() {
  document.getElementById('btnSaveCfg')?.addEventListener('click', () => {
    const cfg = document.getElementById('cfgEditor')?.value;
    fetch('/api/config', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({config:cfg}) })
      .then(r => r.json()).then(d => toast(d.success ? 'Config saved!' : 'Error: '+d.error, d.success ? 'success' : 'error'));
  });
  document.getElementById('btnResetCfg')?.addEventListener('click', () => {
    if (confirm('Reset to last saved config?')) { loadConfig(); toast('Reset','info'); }
  });
}

/* ─── AUTO FILL MODE (target type detection) ─── */
function autoFillMode() {
  const val  = q('#inp-target')?.value.trim() || '';
  const hint = document.getElementById('targetHint');
  const badge= document.getElementById('tgtTypeBadge');
  const sugg = document.getElementById('tgtSuggest');
  if (!hint || !badge || !sugg) return;

  if (!val) { hint.style.display = 'none'; return; }

  // Detection patterns
  const isIPv4   = /^(\d{1,3}\.){3}\d{1,3}$/.test(val);
  const isCIDR   = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(val);
  const isWild   = val.startsWith('*.');
  const isDomain = !isIPv4 && !isCIDR && /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(val.replace(/^\*\./, ''));

  let type, suggest, modeKey;
  if (isCIDR) {
    type = 'cidr'; suggest = 'CIDR range detected — <strong>Passive</strong> or <strong>Web Analysis</strong> recommended'; modeKey = 'passive';
  } else if (isIPv4) {
    type = 'ip'; suggest = 'IPv4 address — <strong>Web Analysis</strong> or <strong>Port Scan</strong> recommended'; modeKey = 'web';
  } else if (isWild) {
    type = 'wildcard'; suggest = 'Wildcard — <strong>Full Recon</strong> recommended'; modeKey = 'recon';
  } else if (isDomain) {
    type = 'domain'; suggest = 'Domain — <strong>Full Recon</strong> recommended'; modeKey = 'recon';
  } else {
    hint.style.display = 'none'; return;
  }

  badge.className = 'tgt-badge ' + type;
  badge.textContent = type.toUpperCase();
  sugg.innerHTML = suggest;
  hint.style.display = 'flex';

  // Auto-select matching mode card if not yet manually changed
  if (!S.modeManuallySet && modeKey) {
    const card = document.querySelector(`.mode-card[data-mode="${modeKey}"]`);
    if (card) {
      document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('sel'));
      card.classList.add('sel');
      card.querySelector('input').checked = true;
      updateCmd();
    }
  }
}

/* ─── TOOLS ─── */
function checkTools() {
  const wrap = document.getElementById('toolsCategorized');
  if (!wrap) return;
  wrap.innerHTML = '<div class="loading"><div class="spin"></div><span>Checking tools...</span></div>';

  fetch('/api/tools/check').then(r => r.json()).then(data => {
    // Group by category
    const cats = {};
    Object.entries(data).forEach(([name, info]) => {
      const cat = info.category || 'Other';
      if (!cats[cat]) cats[cat] = [];
      cats[cat].push({ name, ...info });
    });

    const total     = Object.keys(data).length;
    const installed = Object.values(data).filter(t => t.installed).length;
    const missing   = total - installed;

    // Update summary badge
    const sumEl = document.getElementById('toolsSummary');
    if (sumEl) sumEl.innerHTML = `<strong>${installed}</strong> / ${total} installed &nbsp;·&nbsp; <span style="color:var(--hot)">${missing} missing</span>`;

    const CAT_ICONS = {
      'Subdomains':  '🌐',
      'DNS':         '🔍',
      'Web':         '📸',
      'Crawl/Fuzz':  '🕷️',
      'Port Scan':   '🔌',
      'Vulns':       '🔴',
      'Secrets':     '🔑',
      'Utilities':   '⚙️',
      'Other':       '📦',
    };

    wrap.innerHTML = Object.entries(cats).map(([catName, tools]) => {
      const catOk   = tools.filter(t => t.installed).length;
      const icon    = CAT_ICONS[catName] || '📦';
      const toolCards = tools.map(t => `
        <div class="tool-card ${t.installed ? 'installed' : 'missing'}">
          <div class="tool-status-dot ${t.installed ? 'ok' : 'miss'}"></div>
          <div class="tool-body">
            <div class="tool-name-row">
              <span class="tool-nm">${esc(t.name)}</span>
              ${t.installed && t.version
                ? `<span class="tool-ver">v${esc(t.version)}</span>`
                : t.installed ? '' : '<span class="tool-miss-badge">not found</span>'}
            </div>
            <div class="tool-desc">${esc(t.description || '')}</div>
            ${t.path ? `<div class="tool-path">${esc(t.path)}</div>` : ''}
          </div>
        </div>`).join('');

      return `<div class="tool-category">
        <div class="tool-cat-header">
          <div class="tool-cat-icon">${icon}</div>
          <div class="tool-cat-name">${esc(catName)}</div>
          <div class="tool-cat-count">${catOk}/${tools.length}</div>
        </div>
        <div class="tool-grid">${toolCards}</div>
      </div>`;
    }).join('');

    // Re-attach recheck button
    document.getElementById('btnCheckTools')?.addEventListener('click', () => checkTools(), {once:true});
  }).catch(err => {
    if (wrap) wrap.innerHTML = '<div style="color:var(--hot);padding:20px">Failed to check tools. Server error.</div>';
    console.error(err);
  });
}

/* ─── SETTINGS (reconftw.cfg categorized editor) ─── */
let S_settingsOriginal = null;

function loadSettings() {
  const panels = document.getElementById('settingsPanels');
  if (!panels) return;
  panels.innerHTML = '<div class="loading"><div class="spin"></div><span>Loading settings...</span></div>';

  fetch('/api/config/sections').then(r => r.json()).then(data => {
    if (data.error) { panels.innerHTML = `<div style="color:var(--hot);padding:20px">${esc(data.error)}</div>`; return; }
    S_settingsOriginal = JSON.parse(JSON.stringify(data.sections)); // deep clone
    renderSettingsPanels(data.sections);
  }).catch(() => { panels.innerHTML = '<div style="color:var(--hot);padding:20px">Failed to load config</div>'; });
}

const SEC_ICONS = {
  'General':'⚙️','API Keys':'🔑','OSINT':'🕵️','Subdomains':'🌐',
  'Web Analysis':'🌍','Vulnerabilities':'🔴','Performance':'⚡',
  'Notifications':'🔔','Axiom / VPS':'☁️','AI / Reports':'🤖',
};

function renderSettingsPanels(sections) {
  const panels = document.getElementById('settingsPanels');
  if (!panels) return;
  panels.innerHTML = `<div class="settings-grid">${
    sections.map((sec, si) => {
      const icon  = SEC_ICONS[sec.name] || '📋';
      const open  = si === 0 ? 'open' : '';
      const rows  = sec.items.map(item => buildSettingRow(item)).join('');
      return `<div class="settings-panel ${open}" data-sec="${si}">
        <div class="settings-panel-head" onclick="toggleSettingsPanel(this)">
          <span class="sp-icon">${icon}</span>
          <span class="sp-title">${esc(sec.name)}</span>
          <span class="sp-count">${sec.items.length} settings</span>
          <span class="sp-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg></span>
        </div>
        <div class="settings-panel-body">
          <div class="settings-rows">${rows}</div>
        </div>
      </div>`;
    }).join('')
  }</div>`;
}

function buildSettingRow(item) {
  const k = item.key, v = item.value, kind = item.kind;
  let ctrl = '';
  if (kind === 'bool') {
    const chk = v === 'true' ? 'checked' : '';
    ctrl = `<label class="stog-wrap"><input type="checkbox" data-cfg-key="${k}" ${chk}><div class="stog"></div></label>`;
  } else if (kind === 'int') {
    ctrl = `<input type="number" class="sinput narrow" data-cfg-key="${k}" value="${esc(v)}">`;
  } else if (kind === 'select' && k === 'PERF_PROFILE') {
    const opts = ['normal','fast','slow'].map(o => `<option value="${o}" ${v===o?'selected':''}>${o}</option>`).join('');
    ctrl = `<select class="s-select" data-cfg-key="${k}">${opts}</select>`;
  } else {
    // Sensitive keys → password-style or wide text
    const isSensitive = /TOKEN|API_KEY|PASSWORD|SECRET|SERVER/.test(k);
    const inputType   = isSensitive ? 'password' : 'text';
    const wideClass   = v.length > 20 ? 'wide' : '';
    ctrl = `<input type="${inputType}" class="sinput ${wideClass}" data-cfg-key="${k}" value="${esc(v)}" autocomplete="off" spellcheck="false">`;
  }
  return `<div class="setting-row">
    <div class="setting-info">
      <div class="setting-key">${esc(k)}</div>
      ${kind !== 'bool' ? `<div class="setting-val-text">${esc(v)}</div>` : ''}
    </div>
    <div class="setting-ctrl">${ctrl}</div>
  </div>`;
}

function toggleSettingsPanel(head) {
  const panel = head.closest('.settings-panel');
  if (panel) panel.classList.toggle('open');
}

function collectSettingsValues() {
  const vals = {};
  document.querySelectorAll('[data-cfg-key]').forEach(el => {
    const key = el.dataset.cfgKey;
    if (el.type === 'checkbox') {
      vals[key] = el.checked ? 'true' : 'false';
    } else {
      vals[key] = el.value;
    }
  });
  return vals;
}

function saveSettings() {
  // First load the raw config, then patch all changed values
  fetch('/api/config').then(r => r.json()).then(d => {
    let cfg = d.config;
    const vals = collectSettingsValues();
    Object.entries(vals).forEach(([key, val]) => {
      // Replace the value in raw config preserving comments
      const re = new RegExp(`^(${key}=)[^\\n#]*`, 'm');
      if (re.test(cfg)) {
        cfg = cfg.replace(re, `$1${val}`);
      }
    });
    return fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config: cfg })
    });
  }).then(r => r.json()).then(d => {
    toast(d.success ? '✓ Settings saved!' : 'Error: ' + d.error, d.success ? 'success' : 'error');
    if (d.success) loadSettings();
  }).catch(() => toast('Failed to save settings', 'error'));
}

function initSettingsActions() {
  document.getElementById('btnSaveSettings')?.addEventListener('click', saveSettings);
  document.getElementById('btnResetSettings')?.addEventListener('click', () => {
    if (confirm('Reset settings to last saved state?')) { loadSettings(); toast('Reset', 'info'); }
  });
}

/* ─── TOAST ─── */
function toast(msg, type = 'info') {
  const stack = document.getElementById('toastStack');
  if (!stack) return;
  const icons = {
    success:'<svg class="toast-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error:  '<svg class="toast-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    info:   '<svg class="toast-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = (icons[type]||icons.info) + `<span>${esc(msg)}</span>`;
  stack.appendChild(el);
  setTimeout(() => { el.style.transition = 'opacity .3s,transform .3s'; el.style.opacity = '0'; el.style.transform = 'translateX(16px)'; setTimeout(() => el.remove(), 320); }, 3000);
}

/* ─── HELPERS ─── */
const q = s => document.querySelector(s);
const setText = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

/* ─── BOOT ─── */
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initThemes();
  initSocket();
  initNav();
  initMobileNav();
  initModes();
  initScanActions();
  initTerminal();
  initResultsActions();
  initConfigActions();
  initSettingsActions();
  updateCmd();
  initLiveModules();
  updateLiveModuleList();
  setTimeout(loadResults, 800);

  // Try fetch version from git
  fetch('/api/status').then(r => r.json()).then(() => {}).catch(() => {});
});
