import time
from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from src.database import User, db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from datetime import datetime
from datetime import timedelta
from flasgger import swag_from

auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth.post("/register")
@swag_from("./docs/auth/register.yaml")
def register():
    username = request.json["username"]  # type: ignore
    email = request.json["email"]  # type: ignore
    password = request.json["password"]  # type: ignore

    if len(password) < 6:
        return jsonify({"error": "Password is too short"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username is too short"}), 400

    if not username.isalnum() or " " in username:
        return jsonify({"error": "Username must be alphanumeric, also no spaces"}), 400

    if not validators.email(email):
        return jsonify({"error": "Email is not valid"}), 400

    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "Email is taken"}), 409

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "Username is taken"}), 409

    pwd_hash = generate_password_hash(password)

    user = User(username=username, password=pwd_hash,  # type: ignore
                email=email)  # type: ignore
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "message": "User created",
        "user": {
            "username": username,
            "email": email
        }
    }), 201


@auth.post("/login")
@swag_from("./docs/auth/login.yaml")
def login():
    email = request.json.get("email", "")  # type: ignore
    password = request.json.get("password", "")  # type: ignore

    user = User.query.filter_by(email=email).first()

    if user:
        is_pass_correct = check_password_hash(user.password, password)

        if is_pass_correct:
            expires = timedelta(minutes=15)
            refresh = create_refresh_token(identity=user.username)
            access = create_access_token(
                identity=user.username,
                expires_delta=expires,
                additional_claims={"debug_timestamp": int(
                    time.time())}
            )

            return jsonify({
                "user": {
                    "username": user.username,
                    "email": user.email
                },
                "tokens": {
                    "refresh": refresh,
                    "access": access,
                    "created_at": datetime.now().isoformat(),
                    "server_time": int(time.time())
                }
            }), 200

    return jsonify({"error": "Wrong Credentials"}), 401


@auth.get("/me")
@jwt_required()
def me():
    username = get_jwt_identity()

    user = User.query.filter_by(username=username).first()

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user.username,
        "email": user.email
    }), 200


@auth.post("/token/refresh")
@jwt_required(refresh=True)
def refresh_user_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        "access": access
    }), 200
