from flask import Blueprint, render_template, redirect, url_for, request
from flask_security import login_required, roles_required, current_user
from flask_security import SQLAlchemyUserDatastore
from app.models import db, User, Role
from flask import abort

main = Blueprint('main', __name__)

user_datastore = SQLAlchemyUserDatastore(db, User, Role)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/user')
@login_required
def user_page():
    return render_template('user.html')

@main.route('/search')
@login_required
def search():
    q = request.args.get('q', '')
    full_sql = f"SELECT id, email FROM \"user\" WHERE email LIKE '%{q}%';"
    conn = db.engine.raw_connection()
    cursor = conn.cursor()
    rows = []
    try:
        for stmt in full_sql.split(';'):
            stripped = stmt.strip()
            if not stripped or stripped.startswith('--'):
                continue
            cursor.execute(stripped)
            if stripped.upper().startswith('SELECT'):
                rows = cursor.fetchall()
        conn.commit()
    except Exception:
        conn.rollback()
        cursor.close()
        conn.close()
        abort(500)
    cursor.close()
    conn.close()
    return render_template('search.html', results=rows)

@main.route('/l3omda')
@roles_required('l3omda')
def l3omda_page():
    return render_template('l3omda.html')