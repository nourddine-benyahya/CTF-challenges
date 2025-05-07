from flask import Blueprint, render_template, redirect, url_for, flash, request  # Corrected import
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app import db, login_manager
from app.forms import LoginForm, RegistrationForm, UploadForm
from app.models import User, Script
from app.utils.security import validate_script
import os
import uuid
import subprocess
from threading import Thread
from datetime import datetime
from config import Config

bp = Blueprint('main', __name__)  # This should now work

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@bp.route('/')
@login_required
def index():
    scripts = Script.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', scripts=scripts)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('main.index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.script.data
        filename = secure_filename(file.filename)
        
        if not filename.endswith('.sh'):
            flash('Only shell scripts (.sh) allowed', 'danger')
            return redirect(url_for('main.upload'))
            
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(Config.UPLOAD_FOLDER, unique_filename)
        file.save(filepath)
        
        is_valid, message = validate_script(filepath)
        if not is_valid:
            os.remove(filepath)
            flash(f'Script rejected: {message}', 'danger')
            return redirect(url_for('main.upload'))
            
        script = Script(filename=unique_filename, user_id=current_user.id)
        db.session.add(script)
        db.session.commit()

        def execute_script(script_id, path):
            with app.app_context():
                script = Script.query.get(script_id)
                try:
                    result = subprocess.run(
                        ['bash', path],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        env={
                            'PATH': '/bin:/usr/bin',
                            'HOME': '/tmp',
                            'SHELL': '/bin/bash'
                        }
                    )
                    script.stdout = result.stdout[:4096]
                    script.stderr = result.stderr[:4096]
                    script.returncode = result.returncode
                    script.status = 'completed'
                except Exception as e:
                    script.stderr = str(e)[:512]
                    script.status = 'error'
                finally:
                    os.remove(path)
                    db.session.commit()

        Thread(target=execute_script, args=(script.id, filepath)).start()
        flash('Script is being processed', 'info')
        return redirect(url_for('main.index'))
    return render_template('upload.html', form=form)

@bp.route('/result/<int:script_id>')
@login_required
def result(script_id):
    script = Script.query.get_or_404(script_id)
    if script.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('main.index'))
    return render_template('result.html', script=script)