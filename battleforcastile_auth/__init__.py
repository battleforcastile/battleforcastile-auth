import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Api
from flask_bcrypt import Bcrypt

from battleforcastile_auth.endpoints.prometheus import PrometheusResource

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))

#######################
#### Configuration ####
#######################

# Create the instances of the Flask extensions (flask-sqlalchemy, flask-login, etc.) in
# the global scope, but without any arguments passed in.  These instances are not attached
# to the application at this point.

db = SQLAlchemy()


######################################
#### Application Factory Function ####
######################################

def create_app(config_filename='development_config.py'):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object('config')
    if (
            os.path.isdir(os.path.join(CURRENT_PATH,'..', 'instance')) and
            os.path.isfile(os.path.join(CURRENT_PATH, '..', 'instance', config_filename))
        ):
        app.config.from_pyfile(config_filename)

    initialize_extensions(app)
    register_endpoints(app)
    register_triggers(app)

    return app


def initialize_extensions(app):
    # Since the application instance is now created, pass it to each Flask
    # extension instance to bind it to the Flask application instance (app)
    db.init_app(app)
    Migrate(app, db)
    Bcrypt(app)


def register_endpoints(app):
    from battleforcastile_auth.endpoints.users import UserListResource, GetUserResource, UserLogin
    from battleforcastile_auth.endpoints.root import RootResource

    api = Api(app)

    api.add_resource(UserListResource, '/api/v1/account/create/')
    api.add_resource(UserLogin, '/api/v1/account/login/')
    api.add_resource(GetUserResource, '/api/v1/account/')

    api.add_resource(PrometheusResource, '/metrics')

    api.add_resource(RootResource, '/')


def register_triggers(app):
    pass
