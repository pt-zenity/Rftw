#!/usr/bin/env python3
"""
reconFTW Web UI - Professional Glass Morphism Interface
Flask + SocketIO backend for running reconFTW with real-time output
"""

import os
import sys
import json
import subprocess
import threading
import time
import glob
import signal
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'reconftw-webui-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

RECONFTW_PATH = '/home/reconftw'
RECON_DIR = os.path.join(RECONFTW_PATH, 'Recon')

# Track running processes
active_processes = {}
scan_history = []

def get_recon_results():
    """Get list of completed recon results"""
    results = []
    if os.path.exists(RECON_DIR):
        for target_dir in sorted(os.listdir(RECON_DIR), reverse=True):
            full_path = os.path.join(RECON_DIR, target_dir)
            if os.path.isdir(full_path):
                # Count findings
                subs_file = os.path.join(full_path, 'subdomains', 'subdomains.txt')
                webs_file = os.path.join(full_path, 'webs', 'webs_all.txt')
                vulns_dirs = {
                    'critical': os.path.join(full_path, 'nuclei_output', 'critical.txt'),
                    'high': os.path.join(full_path, 'nuclei_output', 'high.txt'),
                    'medium': os.path.join(full_path, 'nuclei_output', 'medium.txt'),
                    'low': os.path.join(full_path, 'nuclei_output', 'low.txt'),
                }

                subs_count = count_file_lines(subs_file)
                webs_count = count_file_lines(webs_file)
                vulns = {}
                for sev, path in vulns_dirs.items():
                    vulns[sev] = count_file_lines(path)

                # Get modification time
                mtime = os.path.getmtime(full_path)
                mod_time = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')

                results.append({
                    'target': target_dir,
                    'path': full_path,
                    'subdomains': subs_count,
                    'webs': webs_count,
                    'vulns': vulns,
                    'modified': mod_time,
                    'has_screenshots': os.path.exists(os.path.join(full_path, 'screenshots')),
                    'has_nuclei': os.path.exists(os.path.join(full_path, 'nuclei_output')),
                    'has_osint': os.path.exists(os.path.join(full_path, 'osint')),
                })
    return results

def count_file_lines(filepath):
    """Count non-empty lines in file"""
    try:
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            with open(filepath, 'r', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
    except:
        pass
    return 0

def read_file_content(filepath, max_lines=500):
    """Read file content safely"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
                if len(lines) > max_lines:
                    return lines[:max_lines], len(lines)
                return lines, len(lines)
    except:
        pass
    return [], 0

def build_reconftw_command(params):
    """Build the reconFTW command from UI parameters"""
    cmd = ['/bin/bash', os.path.join(RECONFTW_PATH, 'reconftw.sh')]

    # Target
    if params.get('target'):
        cmd.extend(['-d', params['target']])
    elif params.get('list_file'):
        cmd.extend(['-l', params['list_file']])

    # Mode
    mode = params.get('mode', 'r')
    mode_map = {
        'recon': '-r',
        'subdomains': '-s',
        'passive': '-p',
        'all': '-a',
        'web': '-w',
        'osint': '-n',
        'zen': '-z',
    }
    if mode in mode_map:
        cmd.append(mode_map[mode])

    # Output directory
    if params.get('output'):
        cmd.extend(['-o', params['output']])

    # Extra flags
    if params.get('deep'):
        cmd.append('--deep')
    if params.get('ai'):
        cmd.append('--ai')
    if params.get('incremental'):
        cmd.append('--incremental')
    if params.get('no_parallel'):
        cmd.append('--no-parallel')
    if params.get('quiet'):
        cmd.append('--quiet')
    if params.get('rate_limit'):
        cmd.extend(['-q', str(params['rate_limit'])])
    if params.get('out_of_scope'):
        cmd.extend(['-x', params['out_of_scope']])
    if params.get('in_scope'):
        cmd.extend(['-i', params['in_scope']])

    return cmd

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """Get current scan status"""
    return jsonify({
        'active_scans': len(active_processes),
        'scans': {
            pid: {
                'target': info['target'],
                'mode': info['mode'],
                'started': info['started'],
                'status': info['status']
            }
            for pid, info in active_processes.items()
        }
    })

@app.route('/api/results')
def api_results():
    """Get recon results list"""
    return jsonify(get_recon_results())

@app.route('/api/results/<target>')
def api_target_results(target):
    """Get detailed results for a target"""
    target_dir = os.path.join(RECON_DIR, target)
    if not os.path.exists(target_dir):
        return jsonify({'error': 'Target not found'}), 404

    data = {
        'target': target,
        'files': {}
    }

    # Key result files
    file_map = {
        'subdomains': 'subdomains/subdomains.txt',
        'webs': 'webs/webs_all.txt',
        'hosts': 'hosts/hosts.txt',
        'vulns_critical': 'nuclei_output/critical.txt',
        'vulns_high': 'nuclei_output/high.txt',
        'vulns_medium': 'nuclei_output/medium.txt',
        'vulns_low': 'nuclei_output/low.txt',
        'vulns_info': 'nuclei_output/info.txt',
        'emails': 'osint/emails.txt',
        'endpoints': 'webs/endpoints.txt',
        'js_files': 'webs/js_files.txt',
        'ports': 'hosts/portscan_active.txt',
        'portscan': 'hosts/portscan_active.txt',
        'gf_sqli': '.tmp/gf_sqli.txt',
        'gf_xss': '.tmp/gf_xss.txt',
        'gf_lfi': '.tmp/gf_lfi.txt',
        'gf_ssrf': '.tmp/gf_ssrf.txt',
        'google_dorks': 'osint/google_dorks.txt',
        'github_dorks': 'osint/github_dorks.txt',
        'technologies': '.tmp/web_full_info.txt',
        'wordlist': 'webs/wordlist.txt',
        'favicon': '.tmp/favicon.csv',
    }

    for key, rel_path in file_map.items():
        full_path = os.path.join(target_dir, rel_path)
        lines, total = read_file_content(full_path, max_lines=200)
        if total > 0:
            data['files'][key] = {
                'lines': [l.rstrip('\n') for l in lines],
                'total': total,
                'path': rel_path
            }

    # Screenshots
    screenshots_dir = os.path.join(target_dir, 'screenshots')
    if os.path.exists(screenshots_dir):
        screenshots = [f for f in os.listdir(screenshots_dir) if f.endswith('.png')]
        data['screenshots'] = screenshots[:20]

    return jsonify(data)

@app.route('/api/file/<target>')
def api_get_file(target):
    """Get specific file content"""
    filepath = request.args.get('path', '')
    if not filepath:
        return jsonify({'error': 'No path provided'}), 400

    full_path = os.path.join(RECON_DIR, target, filepath)
    # Security: ensure we stay within RECON_DIR
    real_path = os.path.realpath(full_path)
    real_recon = os.path.realpath(RECON_DIR)
    if not real_path.startswith(real_recon):
        return jsonify({'error': 'Access denied'}), 403

    lines, total = read_file_content(full_path, max_lines=1000)
    return jsonify({
        'lines': [l.rstrip('\n') for l in lines],
        'total': total
    })

@app.route('/api/config')
def api_get_config():
    """Get reconFTW config"""
    config_path = os.path.join(RECONFTW_PATH, 'reconftw.cfg')
    try:
        with open(config_path, 'r') as f:
            return jsonify({'config': f.read()})
    except:
        return jsonify({'error': 'Config not found'}), 404

@app.route('/api/config', methods=['POST'])
def api_save_config():
    """Save reconFTW config"""
    data = request.get_json()
    if not data or 'config' not in data:
        return jsonify({'error': 'No config provided'}), 400

    config_path = os.path.join(RECONFTW_PATH, 'reconftw.cfg')
    try:
        # Backup existing config
        backup_path = config_path + '.backup'
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                with open(backup_path, 'w') as b:
                    b.write(f.read())

        with open(config_path, 'w') as f:
            f.write(data['config'])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/check')
def api_check_tools():
    """Check installed tools with version, category, description"""
    TOOL_CATALOG = {
        # ── Subdomain Enumeration ──────────────────────────────────────────
        'subfinder':   {'cat':'Subdomains',  'desc':'Fast passive subdomain enum',               'ver_flag':'--version'},
        'amass':       {'cat':'Subdomains',  'desc':'In-depth attack surface mapping',            'ver_flag':'--version'},
        'assetfinder': {'cat':'Subdomains',  'desc':'Find related domains and subdomains',        'ver_flag':None},
        'findomain':   {'cat':'Subdomains',  'desc':'Subdomain discovery via cert logs & APIs',   'ver_flag':'--version'},
        'crtsh':       {'cat':'Subdomains',  'desc':'crt.sh certificate transparency lookup',     'ver_flag':None},
        'sublist3r':   {'cat':'Subdomains',  'desc':'Subdomain enum using multiple sources',      'ver_flag':'--version'},
        # ── DNS ───────────────────────────────────────────────────────────
        'dnsx':        {'cat':'DNS',         'desc':'Fast DNS toolkit & resolver',                'ver_flag':'--version'},
        'massdns':     {'cat':'DNS',         'desc':'High-performance DNS stub resolver',         'ver_flag':None},
        'puredns':     {'cat':'DNS',         'desc':'DNS resolver & brute-force tool',            'ver_flag':'--version'},
        'dnsvalidator':{'cat':'DNS',         'desc':'Valid DNS resolver list maintainer',         'ver_flag':'--version'},
        # ── Web Probing & Screenshots ──────────────────────────────────────
        'httpx':       {'cat':'Web',         'desc':'Fast HTTP probing & tech detection',         'ver_flag':'--version'},
        'gowitness':   {'cat':'Web',         'desc':'Web screenshot utility using Chrome',        'ver_flag':'--version'},
        'aquatone':    {'cat':'Web',         'desc':'Visual inspection across large scopes',      'ver_flag':'--version'},
        'eyewitness':  {'cat':'Web',         'desc':'Web screenshot and reporting tool',          'ver_flag':'--version'},
        # ── Crawling & Fuzzing ─────────────────────────────────────────────
        'katana':      {'cat':'Crawl/Fuzz',  'desc':'Next-gen web crawling framework',            'ver_flag':'--version'},
        'hakrawler':   {'cat':'Crawl/Fuzz',  'desc':'Simple, fast web crawler for recon',        'ver_flag':None},
        'ffuf':        {'cat':'Crawl/Fuzz',  'desc':'Fast web fuzzer for dir/param discovery',   'ver_flag':'-V'},
        'gau':         {'cat':'Crawl/Fuzz',  'desc':'Fetch URLs from AlienVault, Wayback etc',   'ver_flag':'--version'},
        'waybackurls': {'cat':'Crawl/Fuzz',  'desc':'Fetch Wayback Machine URLs',                'ver_flag':None},
        # ── Port Scanning ─────────────────────────────────────────────────
        'nmap':        {'cat':'Port Scan',   'desc':'The gold standard network scanner',         'ver_flag':'--version'},
        'naabu':       {'cat':'Port Scan',   'desc':'Fast port scanner built with nmap',         'ver_flag':'--version'},
        'masscan':     {'cat':'Port Scan',   'desc':'Mass IP port scanner (very fast)',          'ver_flag':'--version'},
        # ── Vulnerability Scanning ────────────────────────────────────────
        'nuclei':      {'cat':'Vulns',       'desc':'Template-based vulnerability scanner',      'ver_flag':'--version'},
        'dalfox':      {'cat':'Vulns',       'desc':'XSS scanning & parameter analysis',         'ver_flag':'version'},
        'sqlmap':      {'cat':'Vulns',       'desc':'Automatic SQL injection detection',         'ver_flag':'--version'},
        'gf':          {'cat':'Vulns',       'desc':'Grep patterns for interesting params',      'ver_flag':None},
        # ── Secrets & OSINT ───────────────────────────────────────────────
        'trufflehog':  {'cat':'Secrets',     'desc':'Find leaked credentials in git history',    'ver_flag':'--version'},
        'gitleaks':    {'cat':'Secrets',     'desc':'Detect secrets & passwords in git repos',   'ver_flag':'--version'},
        # ── Utilities ─────────────────────────────────────────────────────
        'anew':        {'cat':'Utilities',   'desc':'Append new lines to files (dedup)',         'ver_flag':None},
        'gotator':     {'cat':'Utilities',   'desc':'DNS permutation generator',                 'ver_flag':'--version'},
        'interlace':   {'cat':'Utilities',   'desc':'Asynchronous task runner for pentest',      'ver_flag':'--version'},
        'notify':      {'cat':'Utilities',   'desc':'Stream output to Slack/Discord/Telegram',   'ver_flag':'--version'},
        'tlsx':        {'cat':'Utilities',   'desc':'Fast TLS data extractor',                   'ver_flag':'--version'},
        'interactsh-client':{'cat':'Utilities','desc':'Out-of-band interaction detection',       'ver_flag':'--version'},
    }

    import re as _re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check_one(tool, meta):
        which = subprocess.run(['which', tool], capture_output=True, text=True)
        installed = which.returncode == 0
        path = which.stdout.strip() if installed else None
        version = None

        if installed and meta.get('ver_flag'):
            try:
                vr = subprocess.run(
                    [tool, meta['ver_flag']],
                    capture_output=True, text=True, timeout=4
                )
                raw = (vr.stdout + vr.stderr).strip()
                # Strip ANSI escape codes first
                raw = _re.sub(r'\x1b\[[0-9;]*m', '', raw)
                # Prefer 3-part versions (vX.Y.Z or X.Y.Z), fall back to 2-part
                matches = _re.findall(r'v?(\d+\.\d+\.\d+)', raw)
                if not matches:
                    matches = _re.findall(r'v?(\d+\.\d+)', raw)
                if matches:
                    version = matches[0]
            except Exception:
                version = None

        return tool, {
            'installed': installed,
            'version': version,
            'path': path,
            'category': meta['cat'],
            'description': meta['desc'],
        }

    results = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(check_one, t, m): t for t, m in TOOL_CATALOG.items()}
        for future in as_completed(futures):
            try:
                name, info = future.result()
                results[name] = info
            except Exception:
                pass

    return jsonify(results)


@app.route('/api/config/sections')
def api_config_sections():
    """Return reconftw.cfg parsed and grouped into named sections"""
    config_path = os.path.join(RECONFTW_PATH, 'reconftw.cfg')
    try:
        with open(config_path, 'r') as f:
            raw = f.read()
    except:
        return jsonify({'error': 'Config not found'}), 404

    import re as _re

    # Define sections: (label, [key prefixes / explicit keys])
    SECTIONS = [
        ('General', [
            'SHOW_COMMANDS','MIN_DISK_SPACE_GB','INCREMENTAL_MODE',
            'PARALLEL_MODE','PERF_PROFILE','CONTINUE_ON_ERROR',
            'OUTPUT_VERBOSITY','DEEP','DIFF','REMOVETMP','REMOVELOG',
            'STRUCTURED_LOGGING','MAX_LOG_FILES','MAX_LOG_AGE_DAYS',
        ]),
        ('API Keys', [
            'GITHUB_TOKENS','GITLAB_TOKENS','SHODAN_API_KEY',
            'WHOISXML_API','PDCP_API_KEY','XSS_SERVER','COLLAB_SERVER',
        ]),
        ('OSINT', [
            'OSINT','GOOGLE_DORKS','GITHUB_DORKS','GITHUB_REPOS',
            'METADATA','EMAILS','DOMAIN_INFO','IP_INFO','API_LEAKS',
            'THIRD_PARTIES','SPOOF','MAIL_HYGIENE','CLOUD_ENUM',
            'GITHUB_LEAKS','SECRETS_ENGINE','SECRETS_SCAN_GIT_HISTORY',
            'SECRETS_VALIDATE',
        ]),
        ('Subdomains', [
            'SUBDOMAINS_GENERAL','SUBPASSIVE','SUBCRT','SUBBRUTE',
            'SUBPERMUTE','SUBIAPERMUTE','SUBTAKEOVER',
            'SUB_RECURSIVE_PASSIVE','DEEP_RECURSIVE_PASSIVE',
            'SUB_RECURSIVE_BRUTE','ZONETRANSFER','ASN_ENUM',
            'SRV_ENUM','NS_DELEGATION','REVERSE_IP',
        ]),
        ('Web Analysis', [
            'WEBPROBEFULL','WEBSCREENSHOT','VIRTUALHOSTS','FAVIRECON',
            'PORTSCANNER','PORTSCAN_ACTIVE','PORTSCAN_PASSIVE',
            'CDN_IP','WAF_DETECTION','NUCLEICHECK','URL_CHECK',
            'JSCHECKS','JS_SUB_EXTRACT','FUZZ','CMS_SCANNER',
            'WORDLIST','PARAM_DISCOVERY','GRAPHQL_CHECK',
        ]),
        ('Vulnerabilities', [
            'VULNS_GENERAL','XSS','TEST_SSL','SSRF_CHECKS',
            'CRLF_CHECKS','LFI','SSTI','SQLI','SQLMAP',
            'BROKENLINKS','SPRAY','COMM_INJ','SMUGGLING',
            'WEBCACHE','BYPASSER4XX','FUZZPARAMS','NUCLEI_DAST',
        ]),
        ('Performance', [
            'NUCLEI_RATELIMIT','HTTPX_RATELIMIT','FFUF_RATELIMIT',
            'DNSX_THREADS','DNSX_RATE_LIMIT','INTERLACE_THREADS',
            'FFUF_THREADS','HTTPX_THREADS','KATANA_THREADS',
            'PARALLEL_JOB_TIMEOUT_SECONDS','AVAILABLE_CORES',
            'MAX_RATE_LIMIT','MIN_RATE_LIMIT',
        ]),
        ('Notifications', [
            'NOTIFICATION','SOFT_NOTIFICATION','SENDZIP','NOTIFY',
            'PRESERVE',
        ]),
        ('Axiom / VPS', [
            'AXIOM_FLEET_NAME','AXIOM_FLEET_COUNT','AXIOM_FLEET_REGIONS',
            'AXIOM_FLEET_SHUTDOWN','AXIOM_FLEET_LAUNCH','AXIOM_EXTRA_ARGS',
        ]),
        ('AI / Reports', [
            'AI_EXECUTABLE','AI_MODEL','AI_REPORT_TYPE','AI_REPORT_PROFILE',
            'AI_MAX_CHARS_PER_FILE','AI_REDACT','AI_STRICT',
            'REPORT_ONLY','EXPORT_FORMAT',
        ]),
    ]

    def parse_value(raw_cfg, key):
        m = _re.search(r'^' + _re.escape(key) + r'=([^\n#]*)', raw_cfg, _re.MULTILINE)
        if not m:
            return None
        v = m.group(1).strip().strip('"').strip("'")
        return v

    sections_out = []
    for sec_name, keys in SECTIONS:
        items = []
        for key in keys:
            val = parse_value(raw, key)
            if val is None:
                continue
            vl = val.lower()
            if vl in ('true', 'false'):
                kind = 'bool'
            elif vl.lstrip('-').isdigit():
                kind = 'int'
            elif key in ('PERF_PROFILE',):
                kind = 'select'
            else:
                kind = 'text'
            items.append({'key': key, 'value': val, 'kind': kind})
        if items:
            sections_out.append({'name': sec_name, 'items': items})

    return jsonify({'sections': sections_out})

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'status': 'Connected to reconFTW WebUI'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

@socketio.on('start_scan')
def handle_start_scan(data):
    """Start a reconFTW scan"""
    sid = request.sid

    # Validate input
    if not data.get('target') and not data.get('list_file'):
        emit('scan_error', {'message': 'No target or list provided'})
        return

    cmd = build_reconftw_command(data)
    target = data.get('target', data.get('list_file', 'multi'))
    mode = data.get('mode', 'recon')

    emit('scan_started', {
        'target': target,
        'mode': mode,
        'command': ' '.join(cmd),
        'timestamp': datetime.now().isoformat()
    })

    def run_scan():
        try:
            env = os.environ.copy()
            env['TERM'] = 'xterm-256color'
            env['FORCE_COLOR'] = '1'

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=RECONFTW_PATH,
                env=env,
                preexec_fn=os.setsid
            )

            scan_id = str(process.pid)
            active_processes[scan_id] = {
                'target': target,
                'mode': mode,
                'started': datetime.now().isoformat(),
                'status': 'running',
                'process': process
            }

            socketio.emit('scan_pid', {'pid': scan_id}, to=sid)

            # Stream output
            for line in iter(process.stdout.readline, ''):
                if line:
                    # Strip ANSI color codes for clean display (keep raw for terminal)
                    socketio.emit('scan_output', {
                        'line': line.rstrip('\n'),
                        'pid': scan_id,
                        'timestamp': time.time()
                    }, to=sid)

            process.wait()
            exit_code = process.returncode

            if scan_id in active_processes:
                active_processes[scan_id]['status'] = 'completed' if exit_code == 0 else 'failed'
                del active_processes[scan_id]

            socketio.emit('scan_completed', {
                'pid': scan_id,
                'target': target,
                'exit_code': exit_code,
                'status': 'completed' if exit_code == 0 else 'failed',
                'timestamp': datetime.now().isoformat()
            }, to=sid)

        except Exception as e:
            socketio.emit('scan_error', {'message': str(e)}, to=sid)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

@socketio.on('stop_scan')
def handle_stop_scan(data):
    """Stop a running scan"""
    pid = data.get('pid')
    if pid and pid in active_processes:
        process = active_processes[pid]['process']
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            active_processes[pid]['status'] = 'stopped'
            del active_processes[pid]
            emit('scan_stopped', {'pid': pid})
        except Exception as e:
            emit('scan_error', {'message': f'Failed to stop scan: {e}'})
    else:
        emit('scan_error', {'message': 'Scan not found or already stopped'})

@socketio.on('get_results')
def handle_get_results(data):
    """Get scan results via websocket"""
    results = get_recon_results()
    emit('results_update', {'results': results})

@app.route('/api/live/stats')
def api_live_stats():
    """Get live file counts from active scan directories"""
    stats = {}
    if active_processes:
        for pid, info in active_processes.items():
            target = info['target']
            target_dir = os.path.join(RECON_DIR, target)
            stats[target] = {
                'subdomains': count_file_lines(os.path.join(target_dir, 'subdomains', 'subdomains.txt')),
                'webs': count_file_lines(os.path.join(target_dir, 'webs', 'webs_all.txt')),
                'vulns_critical': count_file_lines(os.path.join(target_dir, 'nuclei_output', 'critical.txt')),
                'vulns_high': count_file_lines(os.path.join(target_dir, 'nuclei_output', 'high.txt')),
                'vulns_medium': count_file_lines(os.path.join(target_dir, 'nuclei_output', 'medium.txt')),
                'status': info['status'],
            }
    return jsonify(stats)

if __name__ == '__main__':
    print("🔥 reconFTW WebUI starting on port 8080...")
    print(f"📁 reconFTW path: {RECONFTW_PATH}")
    socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
