import json

import pytest
from flask_bcrypt import generate_password_hash

from battleforcastile_auth import create_app, db
from battleforcastile_auth.constants import BCRYPT_LOG_ROUNDS
from battleforcastile_auth.models import User


@pytest.fixture(scope='function')
def test_client():
    flask_app = create_app('testing_config.py')

    # Flask provides a way to test your application by exposing the Werkzeug test Client
    # and handling the context locals for you.
    testing_client = flask_app.test_client()

    # Establish an application context before running the tests.
    ctx = flask_app.app_context()
    ctx.push()

    yield testing_client  # this is where the testing happens!

    ctx.pop()


@pytest.fixture(scope='function')
def init_database():
    flask_app = create_app('testing_config.py')

    with flask_app.app_context():
        from battleforcastile_auth.models import User

        # Create the database and the database table
        db.create_all()

        yield db  # this is where the testing happens!

        db.drop_all()


@pytest.fixture(scope='function')
def user1():
    user = User(
        email='user1@example.com',
        username='user1',
        password=(generate_password_hash('12345'.encode('utf-8'), BCRYPT_LOG_ROUNDS)).decode('utf-8'),
        token='1111111111111111111111111111111111111111'
    )
    return user


@pytest.fixture(scope='function')
def user2():
    user = User(
        email='user2@example.com',
        username='user2',
        password=(generate_password_hash('12345'.encode('utf-8'), BCRYPT_LOG_ROUNDS)).decode('utf-8'),
        token='1111111111111111111111111111111111111111'
    )
    return user
