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
    """Check installed tools"""
    tools = [
        'subfinder', 'amass', 'assetfinder', 'findomain',
        'httpx', 'nuclei', 'nmap', 'ffuf', 'gau', 'waybackurls',
        'hakrawler', 'katana', 'dalfox', 'sqlmap', 'gf',
        'anew', 'dnsx', 'massdns', 'gotator', 'puredns',
        'trufflehog', 'gitleaks', 'gowitness', 'aquatone'
    ]

    tool_status = {}
    for tool in tools:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        tool_status[tool] = result.returncode == 0

    return jsonify(tool_status)

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

if __name__ == '__main__':
    print("🔥 reconFTW WebUI starting on port 8080...")
    print(f"📁 reconFTW path: {RECONFTW_PATH}")
    socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
