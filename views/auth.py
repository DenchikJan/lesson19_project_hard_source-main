from flask_restx import Resource, Namespace
from flask import request, abort

from implemented import auth_service

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get('username', None)
        password = req_json.get('password', None)
        if None in [username, password]:
            abort(400)

        tokens = auth_service.generate_token(username, password)

        return tokens, 201

    def put(self):
        req_json = request.json
        refresh_token = req_json.get('refresh_token')

        tokens = auth_service.check_token(refresh_token)

        return tokens, 201





