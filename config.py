import os

DEBUG = False
SECRET_KEY = os.getenv('SECRET_KEY', '<secret>')
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:////tmp/auth_production.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True
