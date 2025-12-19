import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("CYBERSECURE_SECRET_KEY", "dev_secret_change_me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "CYBERSECURE_DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'cybersecure.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
