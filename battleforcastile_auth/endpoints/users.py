import json
import secrets

from flask import request, abort
from flask_restful import Resource
from flask_bcrypt import generate_password_hash, check_password_hash

from battleforcastile_auth import db
from battleforcastile_auth.constants import BCRYPT_LOG_ROUNDS
from battleforcastile_auth.models import User
from battleforcastile_auth.serializers.users import serialize_user


class UserListResource(Resource):
    def get(self):
        users = User.query.all()

        return [serialize_user(user) for user in users], 200

    def post(self):
        data = json.loads(request.data) if request.data else {}

        # Validate request
        if (
                not data.get('username') or
                not data.get('email') or
                not data.get('password')
        ):
            abort(400)

        user = User(
            username=data['username'],
            email=data['email'],
            password=(generate_password_hash(data['password'].encode('utf-8'), BCRYPT_LOG_ROUNDS)).decode('utf-8'),
            token=secrets.token_hex(20)
        )
        db.session.add(user)
        db.session.commit()

        return serialize_user(user), 201

class UserResource(Resource):
    def post(self):
        data = json.loads(request.data) if request.data else {}

        if (
            not data.get('token')
        ):
            abort(400)

        user = User.query.filter(User.token == data.get('token')).first()
        if user:
            return serialize_user(user), 200
        return '', 404


class UserLogin(Resource):
    def post(self):
        data = json.loads(request.data) if request.data else {}

        # Validate request
        if (
                not data.get('username') or
                not data.get('password')
        ):
            abort(400)

        user = User.query.filter(User.username==data.get('username')).first()

        if not user or not check_password_hash(user.password, data.get('password')):
            abort(401)

        return serialize_user(user), 200