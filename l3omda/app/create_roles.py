from app import create_app
from app.models import db, User, Role
from flask_security import SQLAlchemyUserDatastore
from flask_security.utils import hash_password

app = create_app()
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

with app.app_context():
    db.drop_all()
    db.create_all()
    
    if not Role.query.first():
        l3omda_role = Role(name='l3omda', description='Administrator')
        user_role = Role(name='user', description='Regular user')
        db.session.add(l3omda_role)
        db.session.add(user_role)
        db.session.commit()
