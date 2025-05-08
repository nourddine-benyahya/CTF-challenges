from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import subprocess
import re
from threading import Thread
from extensions import db
from models import User, Script
from forms import RegistrationForm, LoginForm, UploadForm

app = Flask(__name__)
try:
    app.config['SECRET_KEY'] = open('/run/secrets/secret_key').read().strip()
except FileNotFoundError:
    app.config['SECRET_KEY'] = 'MED{H4D4_M4CHI_FL4GE}'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1MB file limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Security configuration
FORBIDDEN_PATTERNS = [
    # Command patterns
    r'^\s*file\b', 
    r'\b(apt|apt-get|yum|dnf|pacman|git|wget|pip|npm|pnpm)\b',
    r'\b(rm|mv|cp|chmod|chown|install|dd|shred|mkfs|fdisk)\b',
    r'\b(cat|rev|read|while|awk|sed|tr|grep|head|tail|more|less|nl|hexdump|xxd|strings)\b',
    r'\b(echo\s+>[^&]|>>|<\s*[^&])\b',  # Redirection
    r'\b(zsh|ed|python|perl|ruby|php|node|ruby|tac|more|echo|debugfs|dd|tar|m4|sh|nl|for|split)\b',
    r'\b(ssh|scp|sftp|ftp|rsync|paste|pr|gzip|zcat|nc|netcat|socat|telnet|nmap)\b',
    r'\b(sudo|ex|su|doas|pkexec|visudo|useradd)\b',
    r'\b(cron|at|base64|od|systemctl|service|kill|pkill|killall)\b',
    r'\$(?:\(|\{)[^)]+',  # Command substitution
    r'`',                # Backticks
    r'\b(alias|exec|source|export)\b',
    
    # Path patterns
    r'/(etc|var|home|root|dev|proc|sys|boot)\b',
    r'\s~/',
    r'\$HOME',
    r'\.\./',            # Path traversal
    r'/\.\.',            # Path traversal
    
    # Special characters
    r'&&',               # Command chaining
    r'\|\|',             # OR operators
    r';',                # Command separator
    r'\\x[0-9a-fA-F]{2}',# Hex escapes
    r'\\(?!n)',          # Backslash escapes
    
    # Network patterns
    r'\b(\d{1,3}\.){3}\d{1,3}\b',  # IP addresses
    r'\b(http|ftp|sftp)://\b',
    r':/\d{1,5}\b'       # Port numbers
    r'\b(sort|cut|fold|fmt|uniq|cmp|comm|join|expand|unexpand)\b',
    r'\b[a-zA-Z]{2}\s+[a-zA-Z]{2}\b',  # Detect split commands (e.g., "ca t")
    r'\$[a-zA-Z]+\$[a-zA-Z]+',          # Variable concatenation (e.g., $a$b)
    r'\\\w+',                            # Escaped commands (e.g., c\at)
    r'\/(\w{1,3}\/){2}',                 # Short path segments (e.g., /???/passwd)
    r'\d{3}',                            # Octal numbers (e.g., \143)
    r'\b(eval|declare)\b',               # Dangerous builtins
    r'\b(sort|cut|fold|fmt|uniq|cmp|comm|join|expand|unexpand)\b',
    r'\b[a-zA-Z]{2}\s+[a-zA-Z]{2}\b',  # Detect split commands (e.g., "ca t")
    r'\$[a-zA-Z]+\$[a-zA-Z]+',          # Variable concatenation (e.g., $a$b)
    r'\\\w+',                            # Escaped commands (e.g., c\at)
    r'\/(\w{1,3}\/){2}',                 # Short path segments (e.g., /???/passwd)
    r'\d{3}',                            # Octal numbers (e.g., \143)
    r'\b(eval|declare)\b',               # Dangerous builtins
]

ALLOWED_SHEBANGS = {
    '#!/bin/bash',
    '#!/bin/sh',
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

def validate_script(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read().lower()
            lines = [line.strip() for line in content.split('\n')]

        # Check shebang line
        if not lines or lines[0] not in [s.lower() for s in ALLOWED_SHEBANGS]:
            return False, "Invalid/missing shebang line"

        # Check for forbidden patterns
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, content, flags=re.IGNORECASE):
                return False, f"Forbidden pattern: {pattern}"

        # Check for path traversal
        if any('../' in line or '/..' in line for line in lines):
            return False, "Path traversal detected"
         # Normalize paths before checking traversal
        normalized = os.path.normpath(content)
        if any(part == '..' for part in normalized.split(os.sep)):
            return False, "Path traversal detected"
        return True, "Validation passed"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

@app.route('/')
@login_required
def index():
    scripts = Script.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', scripts=scripts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_pw
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        if 'script' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('upload'))
        
        file = form.script.data
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('upload'))
        
        filename = secure_filename(file.filename)
        if not filename.endswith('.sh'):
            flash('Only .sh files allowed', 'danger')
            return redirect(url_for('upload'))
        
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Validate script
        is_valid, message = validate_script(filepath)
        if not is_valid:
            os.remove(filepath)
            flash(f'Invalid script: {message}', 'danger')
            return redirect(url_for('upload'))
        
        # Save to database
        script = Script(
            filename=unique_filename,
            user_id=current_user.id,
            status='pending'
        )
        db.session.add(script)
        db.session.commit()

        def execute_script(script_id, path):
            with app.app_context():
                script = Script.query.get(script_id)
                try:
                    # Ensure the script has executable permissions
                    os.chmod(path, 0o700)

                    # Restricted execution environment
                    result = subprocess.run(
                        ['bash', path],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        
                        env={
                            'PATH': '/bin:/usr/bin',
                            'HOME': '/tmp',
                            'SHELL': '/bin/bash'
                        },
                        executable='/bin/bash'
                    )
                    script.stdout = result.stdout[:4096]  # Limit output
                    script.stderr = result.stderr[:4096]
                    script.returncode = result.returncode
                    script.status = 'completed'
                except subprocess.TimeoutExpired:
                    script.stderr = "Execution timed out (30s)"
                    script.status = 'timeout'
                except Exception as e:
                    script.stderr = str(e)[:512]
                    script.status = 'error'
                finally:
                    try:
                        os.remove(path)
                    except Exception as cleanup_error:
                        script.stderr += f"\nCleanup error: {str(cleanup_error)}"
                    db.session.commit()

        Thread(target=execute_script, args=(script.id, filepath)).start()
        flash('Script is being processed', 'info')
        return redirect(url_for('index'))
    return render_template('upload.html', form=form)

@app.route('/result/<int:script_id>')
@login_required
def result(script_id):
    script = Script.query.get_or_404(script_id)
    if script.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
    return render_template('result.html', script=script)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)