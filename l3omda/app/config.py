import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_secret_key')

SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///data.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'dev_salt')
SECURITY_REGISTERABLE = True
SECURITY_SEND_REGISTER_EMAIL = False

FLAG = os.environ.get('FLAG', 'FLAG_NOT_SET')
