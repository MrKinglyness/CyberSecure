from flask import Flask
from flask_login import LoginManager

from config import Config
from models import db, User
from auth import auth_bp, ensure_demo_user
from api import api_bp
from pages import pages_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login_get"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.query.get(int(user_id))

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(pages_bp)

    with app.app_context():
        db.create_all()
        ensure_demo_user()

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
