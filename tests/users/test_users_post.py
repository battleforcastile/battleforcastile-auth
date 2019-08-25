import json

from flask_bcrypt import check_password_hash

from battleforcastile_auth.models import User
from battleforcastile_auth.serializers.users import serialize_user


def test_users_are_successfully_created(init_database, test_client):
    new_user = {
        'username': 'blabla',
        'email': 'blabla@example.com',
        'password': '12345'
    }
    rv = test_client.post('/api/v1/account/create/', data=json.dumps(new_user))

    created_user = User.query.filter_by(username=new_user['username']).first()

    assert rv.status_code == 201
    assert serialize_user(created_user) == json.loads(rv.data)
    assert created_user.password != new_user.get('password')  # Password is hashed
    assert check_password_hash(created_user.password, new_user.get('password'))


def test_users_returns_400_when_payload_is_incomplete(init_database, test_client):
    new_user = {
        'email': 'blabla@example.com',
        'password': '12345'
    }
    rv = test_client.post('/api/v1/account/create/', data=json.dumps(new_user))

    assert rv.status_code == 400

    new_user = {
        'username': 'blabla',
        'password': '12345'
    }
    rv = test_client.post('/api/v1/account/create/', data=json.dumps(new_user))

    assert rv.status_code == 400

    new_user = {
        'email': 'blabla@example.com',
        'username': 'blabla'
    }
    rv = test_client.post('/api/v1/account/create/', data=json.dumps(new_user))

    assert rv.status_code == 400


