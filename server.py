from flask import Flask, jsonify, request, Response
from flask.views import MethodView
import flask_bcrypt
from pydantic import ValidationError
from schema import CreateAdvertisement, UpdateAdvertisement

from models import User, Session, Advertisement
from sqlalchemy.exc import IntegrityError

app = Flask('app')
bcrypt = flask_bcrypt.Bcrypt(app)


def hash_password(password: str) -> str:
    password = password.encode()
    password = bcrypt.generate_password_hash(password)
    password = password.decode()
    return password


def check_password(user_password: str, db_password: str) -> bool:
    user_password = user_password.encode()
    db_password = db_password.encode()
    return bcrypt.check_password_hash(db_password, user_password)


class ApiError(Exception):

    def __init__(self, status_code, msg):
        self.status_code = status_code
        self.msg = msg


@app.errorhandler(ApiError)
def error_handler(err: ApiError):
    http_response = jsonify({'error': err.msg})
    http_response.status_code = err.status_code
    return http_response

@app.before_request
def before_request():
    session = Session()
    request.session = session

@app.after_request
def after_request(http_response: Response):
    request.session.close()
    return http_response


def validate(json_data, schema_cls):
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except ValidationError as err:
        error = err.errors()[0]
        error.pop('ctx', None)
        raise ApiError(400, error)


# def get_user(user_id: int):
#     user = request.session.get(User, user_id)
#     if user is None:
#         raise ApiError(404, "user not found")
#     return user
# def add_user(user: User):
#     try:
#         request.session.add(user)
#         request.session.commit()
#     except IntegrityError:
#         raise ApiError(409, "user already exists")
#     return user

def get_advertisement(s: Session, post_id):
    post_ = s.get(Advertisement, post_id)
    if post_ is None:
        raise ApiError(404, "Такой записи нет")
    return post_


# class UserView(MethodView):
#     def get(self, user_id: int):
#         user = get_user(user_id)
#         return jsonify(user.json())
#
#     def post(self):
#         json_data = validate(request.json, UserCreate)
#         new_user = User(
#             name = json_data["name"],
#             password = hash_password(json_data["password"])
#         )
#         new_user = add_user(new_user)
#         return new_user.json()
#
#
#     def patch(self, user_id: int):
#         json_data = validate(request.json, UserUpdate)
#         if "password" in json_data:
#             json_data["password"] = hash_password(json_data["password"] )
#         user = get_user(user_id)
#         for field, value in json_data.items():
#             setattr(user, field, value)
#         user = add_user(user)
#         return jsonify(user.json())
#
#
#     def delete(self, user_id):
#         user = get_user(user_id)
#         request.session.delete(user)
#         request.session.commit()
#         return jsonify({"status": "deleted"})


class ApiV1(MethodView):
    def get(self, post_id):
        with Session() as s:
            post_ = get_advertisement(s, post_id)
            return jsonify(
                {
                    "id": post_.id,
                    "heading": post_.heading,
                    "description": post_.description,
                    "date_of_creation": post_.date_of_creation,
                    "User_name": post_.user.name,
                    "id_user": post_.user.id,
                }
            )

    def post(self):
        advertisement_data = validate(request.json, CreateAdvertisement)
        with Session() as session:
            new_advertisement = Advertisement(**advertisement_data)
            session.add(new_advertisement)
            session.commit()
            return jsonify({
                'id': new_advertisement.id,
                'heading': new_advertisement.heading,
                'description': new_advertisement.description,
                'user_id': new_advertisement.user_id
            })

    def patch(self, post_id):
        advertisement_data = request.json
        with Session() as session:
            advertisement = session.query(Advertisement).get(post_id)
            for field, value in advertisement_data.items():
                setattr(advertisement, field, value)
            session.add(advertisement)
            session.commit()
            return jsonify({
                'id': advertisement.id,
                'heading': advertisement.heading,
                'description': advertisement.description,
                'user_id': advertisement.user_id
            })


    def delete(self, post_id):
        with Session() as session:
            advertisement = session.query(Advertisement).get(post_id)
            session.delete(advertisement)
            session.commit()
            return jsonify({
                'status': 'deleted'
            })


# user_view = UserView.as_view("user")
#
# app.add_url_rule(
#     "/user/<int:user_id>",
#     view_func=user_view,
#     methods=["GET", "PATCH", "DELETE"]
# )
#
# app.add_url_rule(
#     "/user",
#     view_func=user_view,
#     methods=["POST"]
# )

api_view = ApiV1.as_view("api_v1")

app.add_url_rule(
    "/api/<int:post_id>", view_func=api_view, methods=["GET", "PATCH", "DELETE"]
)
app.add_url_rule("/api", view_func=api_view, methods=["POST"])

app.run()
