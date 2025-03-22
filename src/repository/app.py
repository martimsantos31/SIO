from flask import Flask
from repository.controller.organization import org
from repository.controller.session import session
from repository.controller.subject import subject
from repository.controller.document import doc
from repository.controller.role import role
from flask_cors import CORS

app = Flask(__name__)

CORS(app)


app.register_blueprint(org)
app.register_blueprint(session)
app.register_blueprint(subject)
app.register_blueprint(doc)
app.register_blueprint(role)
