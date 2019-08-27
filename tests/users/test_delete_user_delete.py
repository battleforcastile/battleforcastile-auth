import json

from flask_bcrypt import check_password_hash

from battleforcastile_auth import db
from battleforcastile_auth.models import User
from battleforcastile_auth.serializers.users import serialize_user


def test_user_is_successfully_deleted_with_valid_token(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    delete_user = {
        'token': user1.token
    }
    rv = test_client.delete('/api/v1/account/delete/', data=json.dumps(delete_user))

    assert rv.status_code == 204


def test_user_cannot_be_deleted_due_to_wrong_token(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    delete_user = {
        'token': '12'
    }
    rv = test_client.delete('/api/v1/account/delete/', data=json.dumps(delete_user))

    assert rv.status_code == 404


def test_user_cannot_be_deleted_due_to_missing_token(init_database, test_client, user1):
    db.session.add(user1)
    db.session.commit()

    delete_user = {}
    rv = test_client.delete('/api/v1/account/delete/', data=json.dumps(delete_user))

    assert rv.status_code == 400