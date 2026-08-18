import os
from pathlib import Path


class Config:
    SECRET_KEY = os.environ.get("MIRSAD_SECRET_KEY", "development-only-change-me")
    REQUEST_TIMEOUT = 10
    DATABASE = os.environ.get("MIRSAD_DATABASE", str(Path("instance") / "mirsad.sqlite"))
    DEBUG = os.environ.get("MIRSAD_DEBUG", "0") == "1"
