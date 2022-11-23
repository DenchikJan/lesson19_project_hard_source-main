import hashlib
import base64
import hmac

from dao.user import UserDAO
from constants import PWD_HASH_ITERATIONS, PWD_HASH_SALT


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def create(self, user):
        return self.dao.create(user)

    def update(self, data):
        uid = data.get("id")
        user = self.get_one(uid)

        user.username = data.get('username')
        user.password = data.get('password')
        user.role = data.get('role')

        self.dao.update(user)

    def delete(self, uid):
        self.dao.delete(uid)

    def get_hash(self, password):
        hash_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )
        return base64.b64encode(hash_password)

    def compare_password(self, password_hash, request_password):
        return hmac.compare_digest(
            base64.b64decode(password_hash),
            hashlib.pbkdf2_hmac(
                'sha256',
                request_password.encode('utf-8'),  # Convert the password to bytes
                PWD_HASH_SALT,
                PWD_HASH_ITERATIONS
            )
        )


