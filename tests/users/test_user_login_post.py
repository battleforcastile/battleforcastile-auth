import json

from flask_bcrypt import check_password_hash

from battleforcastile_auth import db
from battleforcastile_auth.models import User
from battleforcastile_auth.serializers.users import serialize_user


def test_user_is_successfully_logged_in(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    login = {
        'username': user1.username,
        'password': '12345'
    }
    rv = test_client.post('/api/v1/account/login/', data=json.dumps(login))

    assert rv.status_code == 200
    assert serialize_user(user1) == json.loads(rv.data)


def test_user_cannot_login_due_to_wrong_password(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    login = {
        'username': user1.username,
        'password': '123456'
    }
    rv = test_client.post('/api/v1/account/login/', data=json.dumps(login))

    assert rv.status_code == 401


def test_users_returns_400_when_payload_is_incomplete(init_database, test_client):
    login = {
        'username': 'blabla@example.com',
    }
    rv = test_client.post('/api/v1/account/login/', data=json.dumps(login))

    assert rv.status_code == 400

    login = {
        'password': '12345'
    }
    rv = test_client.post('/api/v1/account/login/', data=json.dumps(login))

    assert rv.status_code == 400
