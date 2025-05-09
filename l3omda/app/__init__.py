from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore
from .models import db, User, Role

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    app.jinja_env.globals['config'] = app.config

    return app