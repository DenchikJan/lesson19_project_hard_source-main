from flask_restx import Resource, Namespace
from flask import request

from decorators import auth_required, admin_required
from dao.model.user import UserSchema
from implemented import user_service

users_ns = Namespace('users')


@users_ns.route('/')
class UsersView(Resource):
    @admin_required
    def get(self):
        rs = user_service.get_all()
        res = UserSchema(many=True).dump(rs)
        return res, 200

    def post(self):
        req_json = request.json
        req_json['password'] = user_service.get_hash(req_json['password'])
        user_service.create(req_json)

        return "", 201


@users_ns.route('/<int:uid>')
class UserView(Resource):
    @admin_required
    def get(self, uid):
        r = user_service.get_one(uid)
        sm_d = UserSchema().dump(r)
        return sm_d, 200

    @auth_required
    def put(self, uid: int):
        req_json = request.json
        req_json['id'] = uid
        req_json['password'] = user_service.get_hash(req_json['password'])

        user_service.update(req_json)

        return "", 204

    @auth_required
    def delete(self, uid: int):
        user_service.delete(uid)

        return "", 204
