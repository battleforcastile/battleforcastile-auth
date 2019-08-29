import json
import secrets

from flask import request, abort
from flask_restful import Resource
from flask_bcrypt import generate_password_hash, check_password_hash

from battleforcastile_auth import db
from battleforcastile_auth.custom_logging import logging
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
            #  We delete the password from the "data" structure as we don't want to include it into the logging
            data.pop('password') if data.get('password') else None

            logging.info(
                f'[CREATE USER] User could not be created due to missing information',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'create_user',
                    'payload': data
                }
            )
            abort(400)

        if (
                User.query.filter(User.username == data.get('username')).count() or
                User.query.filter(User.email == data.get('email')).count()
        ):
            #  We delete the password from the "data" structure as we don't want to include it into the logging
            data.pop('password')

            logging.info(
                f'[CREATE USER] User could not be created due to already taken username/email',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'create_user',
                    'payload': data
                }
            )
            return 'username/email already taken', 409

        if len(data.get('password')) < MIN_PASSWORD_LENGTH:
            #  We delete the password from the "data" structure as we don't want to include it into the logging
            data.pop('password')

            logging.info(
                f'[CREATE USER] User could not be created due to too short password',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'create_user',
                    'payload': data
                }
            )
            return f'password too short (minimum {MIN_PASSWORD_LENGTH} characters)', 400

        user = User(
            username=data['username'],
            email=data['email'],
            password=(generate_password_hash(data['password'].encode('utf-8'), BCRYPT_LOG_ROUNDS)).decode('utf-8'),
            token=secrets.token_hex(20)
        )
        db.session.add(user)
        db.session.commit()

        #  We delete the password from the "data" structure as we don't want to include it into the logging
        data.pop('password')

        logging.info(
            f'[CREATE USER] User was created',
            {
                'request_id': None,
                'service': 'battleforcastile-auth',
                'username': None,
                'action': 'create_user',
                'payload': data
            }
        )
        return serialize_user(user), 201


class GetUserResource(Resource):
    def post(self):
        data = json.loads(request.data) if request.data else {}

        if (
            not data.get('token')
        ):
            logging.info(
                f'[GET USER] User was not fetched due to missing information',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'get_user',
                    'payload': data
                }
            )
            abort(400)

        user = User.query.filter(User.token == data.get('token')).first()
        if user:
            #  We delete the token from the "data" structure as we don't want to include it into the logging
            data.pop('token')
            logging.info(
                f'[GET USER] User was fetched',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'get_user',
                    'payload': data
                }
            )
            return serialize_user(user), 200

        #  We delete the token from the "data" structure as we don't want to include it into the logging
        data.pop('token')
        logging.info(
            f'[GET USER] User was not found',
            {
                'request_id': None,
                'service': 'battleforcastile-auth',
                'username': None,
                'action': 'get_user',
                'payload': data
            }
        )
        return '', 404


class DeleteUserResource(Resource):
    def delete(self):
        data = json.loads(request.data) if request.data else {}
        if (
            not data.get('token')
        ):

            logging.info(
                f'[DELETE USER] User was not deleted due to missing information',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'delete_user',
                    'payload': data
                }
            )
            abort(400)

        user = User.query.filter(User.token == data.get('token')).first()
        if user:
            db.session.delete(user)
            db.session.commit()

            #  We delete the token from the "data" structure as we don't want to include it into the logging
            data.pop('token')

            logging.info(
                f'[DELETE USER] User was deleted',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'delete_user',
                    'payload': data
                }
            )
            return 'Account deleted', 204

        #  We delete the token from the "data" structure as we don't want to include it into the logging
        data.pop('token')
        logging.info(
            f'[DELETE USER] User was not found',
            {
                'request_id': None,
                'service': 'battleforcastile-auth',
                'username': None,
                'action': 'delete_user',
                'payload': data
            }
        )
        return 'Account not found', 404


class UserLogin(Resource):
    def post(self):
        data = json.loads(request.data) if request.data else {}

        # Validate request
        if (
                not data.get('username') or
                not data.get('password')
        ):
            #  We delete the password from the "data" structure as we don't want to include it into the logging
            data.pop('password') if data.get('password') else None

            logging.info(
                f'[LOGIN USER] User was not logged-in due to missing information',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'login_user',
                    'payload': data
                }
            )
            abort(400)

        user = User.query.filter(User.username==data.get('username')).first()

        if not user or not check_password_hash(user.password, data.get('password')):
            #  We delete the password from the "data" structure as we don't want to include it into the logging
            data.pop('password')

            logging.info(
                f'[LOGIN USER] User was not logged-in due to wrong credentials',
                {
                    'request_id': None,
                    'service': 'battleforcastile-auth',
                    'username': None,
                    'action': 'login_user',
                    'payload': data
                }
            )
            abort(401)

        #  We delete the password from the "data" structure as we don't want to include it into the logging
        data.pop('password')

        logging.info(
            f'[LOGIN USER] User was logged-in',
            {
                'request_id': None,
                'service': 'battleforcastile-auth',
                'username': None,
                'action': 'login_user',
                'payload': data
            }
        )
        return serialize_user(user), 200