from flask import Blueprint

tests = Blueprint("test", __name__)


@tests.route("/", methods=["GET"])
def test():
    return "Hello World"
