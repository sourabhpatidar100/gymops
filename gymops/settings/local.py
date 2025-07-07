from .base import *

SECRET_KEY = config("DJANGO_SECRET_KEY")

DEBUG = True


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}
