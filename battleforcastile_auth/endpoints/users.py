import json
import secrets

from flask import request, abort
from flask_restful import Resource
from flask_bcrypt import generate_password_hash, check_password_hash

from battleforcastile_auth import db
from battleforcastile_auth.constants import BCRYPT_LOG_ROUNDS, MIN_PASSWORD_LENGTH
from battleforcastile_auth.models import User
from battleforcastile_auth.serializers.users import serialize_user


class UserListResource(Resource):
    def post(self):
        data = json.loads(request.data) if request.data else {}

        # Validate request
        if (
                not data.get('username') or
                not data.get('email') or
                not data.get('password')
        ):
            abort(400)

        if (
                User.query.filter(User.username == data.get('username')).count() or
                User.query.filter(User.email == data.get('email')).count()
        ):
            return 'username/email already taken', 409

        if len(data.get('password')) < MIN_PASSWORD_LENGTH:
            return f'password too short (minimum {MIN_PASSWORD_LENGTH} characters)', 400

        user = User(
            username=data['username'],
            email=data['email'],
            password=(generate_password_hash(data['password'].encode('utf-8'), BCRYPT_LOG_ROUNDS)).decode('utf-8'),
            token=secrets.token_hex(20)
        )
        db.session.add(user)
        db.session.commit()

        return serialize_user(user), 201


class GetUserResource(Resource):
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


class DeleteUserResource(Resource):
    def delete(self):
        data = json.loads(request.data) if request.data else {}
        if (
            not data.get('token')
        ):
            abort(400)

        user = User.query.filter(User.token == data.get('token')).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return '', 204
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