import json

from flask_bcrypt import check_password_hash

from battleforcastile_auth import db
from battleforcastile_auth.models import User
from battleforcastile_auth.serializers.users import serialize_user


def test_user_is_successfully_fetched_with_valid_token(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    get_user = {
        'token': user1.token
    }
    rv = test_client.post('/api/v1/get_user/', data=json.dumps(get_user))

    assert rv.status_code == 200
    assert serialize_user(user1) == json.loads(rv.data)


def test_user_cannot_login_due_to_wrong_token(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    get_user = {
        'token': '12'
    }
    rv = test_client.post('/api/v1/get_user/', data=json.dumps(get_user))

    assert rv.status_code == 404


def test_user_cannot_login_due_to_missing_token(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    get_user = {}
    rv = test_client.post('/api/v1/get_user/', data=json.dumps(get_user))

    assert rv.status_code == 400