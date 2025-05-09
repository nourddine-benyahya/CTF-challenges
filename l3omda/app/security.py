from app.models import User, Role
from flask_security import Security, SQLAlchemyUserDatastore

def init_security(app):
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)
    return security