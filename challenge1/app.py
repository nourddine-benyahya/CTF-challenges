from flask import Flask, request, jsonify, render_template, redirect, url_for
import os
import uuid
import subprocess
import re
from threading import Thread

app = Flask("execute_command")
results = {}

# Security configurations
FORBIDDEN_COMMANDS = {
    'cat', 'apt', 'apt-get', 'git', 'rm', 'cd', 'mv', 'cp',
    'wget', 'clone', 'sudo', 'nano', 'vi', 'vim',
    'chmod', 'chown', 'python', 'pip', 'npm', 'yum', 'dnf',
    'kill', 'service', 'systemctl', 'ssh', 'scp', 'ftp', 'echo',
    '>', '>>', '<', '|', '&', ';', '&&', '||', '`', '$('
}

DOCKER_IMAGE = 'ubuntu'  # Pre-configured image with bash

# Secret configuration
secret_path = '/run/secrets/SECRET_KEY'
if os.path.exists(secret_path):
    with open(secret_path) as f:
        app.config['SECRET_KEY'] = f.read().strip()
else:
    app.config['SECRET_KEY'] = 'dev_secret'

def is_valid_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False

def validate_script(content):
    if not content.startswith('#!/'):
        return False, "Script must start with a valid shebang"
    
    forbidden_commands_lower = {cmd.lower() for cmd in FORBIDDEN_COMMANDS}

    for line_num, line in enumerate(content.splitlines(), 1):
        # Remove inline comments and clean the line
        clean_line = re.sub(r'#.*$', '', line).strip()
        if not clean_line:
            continue
        
        # Split into command and arguments
        parts = clean_line.split()
        if not parts:
            continue
            
        first_command = parts[0].strip().lower()
        
        if first_command in forbidden_commands_lower:
            return False, f"Forbidden command '{first_command}' detected on line {line_num}"
            
    return True, ""

@app.route('/')
def index():
    return render_template('index.html', tasks=list(results.keys()))

@app.route('/upload', methods=['POST'])
def upload_script():
    if 'script' not in request.files:
        return render_template('error.html', message='No script file provided'), 400

    file = request.files['script']
    if not file.filename.endswith('.sh'):
        return render_template('error.html', message='Only .sh files allowed'), 400

    content = file.read().decode('utf-8')
    valid, message = validate_script(content)
    if not valid:
        return render_template('error.html', message=message), 400

    task_id = str(uuid.uuid4())
    save_path = f"/tmp/{task_id}.sh"
    
    # Resave the file after validation
    with open(save_path, 'w') as f:
        f.write(content)

    def run_script(path, tid):
        try:
            cmd = [
                'docker', 'run', '--rm',
                '-v', f'{path}:/script.sh:ro',
                '--user', 'nobody',
                '--read-only',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev',
                '--network', 'none',
                DOCKER_IMAGE,
                'bash', '/script.sh'
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            results[tid] = {
                'stdout': proc.stdout,
                'stderr': proc.stderr,
                'returncode': proc.returncode
            }
        except subprocess.TimeoutExpired:
            results[tid] = {'error': 'Script execution timed out'}
        except Exception as e:
            results[tid] = {'error': str(e)}
        finally:
            try:
                os.remove(path)
            except:
                pass

    Thread(target=run_script, args=(save_path, task_id)).start()
    return redirect(url_for('index'))

@app.route('/run/<task_id>', methods=['GET'])
def run_button(task_id):
    if not is_valid_uuid(task_id):
        return render_template('error.html', message='Invalid task ID'), 400
    return redirect(url_for('get_result', task_id=task_id))

@app.route('/result/<task_id>', methods=['GET'])
def get_result(task_id):
    if not is_valid_uuid(task_id):
        return render_template('error.html', message='Invalid task ID'), 400
    if task_id not in results:
        return render_template('pending.html', task_id=task_id)
    return render_template('result.html', task_id=task_id, data=results[task_id])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)