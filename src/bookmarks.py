from flask import Blueprint, request, jsonify
from flask_jwt_extended.view_decorators import jwt_required
from flask_jwt_extended import get_jwt_identity
from src.database import Bookmark, db
import validators
from flasgger import swag_from

bookmarks = Blueprint("bookmarks", __name__, url_prefix="/api/v1/bookmarks")


@bookmarks.route("/", methods=["POST", "GET"])
@jwt_required()
def handle_bookmarks():
    current_user = get_jwt_identity()

    if request.method == "POST":
        body = request.get_json().get("body", "")
        url = request.get_json().get("url", "")

        if not validators.url(url):
            return jsonify({
                "error": "URL already exists"
            }), 409

        bookmark = Bookmark(url=url, body=body, user_id=current_user)
        db.session.add(bookmark)
        db.session.commit()

        return jsonify({
            "id": bookmark.id,
            "url": bookmark.url,
            "short_url": bookmark.short_url,
            "visits": bookmark.visits,
            "body": bookmark.body,
            "created_at": bookmark.created_at,
            "updated_at": bookmark.updated_at
        }), 201

    else:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 5, type=int)

        bookmarks = Bookmark.query.filter_by(
            user_id=current_user).paginate(page=page, per_page=per_page)

        data = []

        for bookmark in bookmarks:
            data.append({
                "id": bookmark.id,
                "url": bookmark.url,
                "short_url": bookmark.short_url,
                "visits": bookmark.visits,
                "body": bookmark.body,
                "created_at": bookmark.created_at,
                "updated_at": bookmark.updated_at
            })

        meta = {
            "page": bookmarks.page,
            "pages": bookmarks.pages,
            "total_count": bookmarks.total,
            "prev_page": bookmarks.prev_num,
            "next_page": bookmarks.next_num,
            "has_next": bookmarks.has_next,
            "has_prev": bookmarks.has_prev
        }

        return jsonify({
            "data": data,
            "meta": meta
        }), 200


@bookmarks.get("/<int:id>")
@jwt_required()
def get_bookmark(id):
    current_user = get_jwt_identity()

    bookmark = Bookmark.query.filter_by(id=id, user_id=current_user).first()

    if not bookmark:
        return jsonify({
            "message": "Item not found"
        }), 404

    return jsonify({
        "id": bookmark.id,
        "url": bookmark.url,
        "short_url": bookmark.short_url,
        "visits": bookmark.visits,
        "body": bookmark.body,
        "created_at": bookmark.created_at,
        "updated_at": bookmark.updated_at
    }), 200


@bookmarks.put("/<int:id>")
@bookmarks.patch("/<int:id>")
@jwt_required()
def edit_bookmark(id):
    current_user = get_jwt_identity()

    bookmark = Bookmark.query.filter_by(id=id, user_id=current_user).first()

    if not bookmark:
        return jsonify({
            "message": "Item not found"
        }), 404

    body = request.get_json().get("body", "")
    url = request.get_json().get("url", "")

    if not validators.url(url):
        return jsonify({
            "error": "Enter a valid URL"
        }), 400

    bookmark.url = url
    bookmark.body = body

    db.session.commit()

    return jsonify({
        "id": bookmark.id,
        "url": bookmark.url,
        "short_url": bookmark.short_url,
        "visits": bookmark.visits,
        "body": bookmark.body,
        "created_at": bookmark.created_at,
        "updated_at": bookmark.updated_at
    }), 200


@bookmarks.delete("/<int:id>")
@jwt_required()
def delete_bookmark(id):
    current_user = get_jwt_identity()

    bookmark = Bookmark.query.filter_by(user_id=current_user, id=id).first()

    if not bookmark:
        return jsonify({
            "error": "Item not found"
        }), 404

    db.session.delete(bookmark)
    db.session.commit()

    return jsonify({}), 204


@bookmarks.get("/stats")
@jwt_required()
@swag_from("./docs/bookmarks/stats.yaml")
def get_stats():
    current_user = get_jwt_identity()

    data = []

    items = Bookmark.query.filter_by(user_id=current_user).all()

    for item in items:
        new_link = {
            "visits": item.visits,
            "url": item.url,
            "id": item.id,
            "short_url": item.short_url
        }
        data.append(new_link)

    return jsonify({
        "data": data
    }), 200
