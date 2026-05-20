import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY", "profile-identity-dev-secret")
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY", SECRET_KEY)
DEBUG = os.getenv("DEBUG", "True") == "True"
ALLOWED_HOSTS = [host.strip() for host in os.getenv("ALLOWED_HOSTS", "*").split(",") if host.strip()]

INSTALLED_APPS = [
    "corsheaders",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "identity",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "identity.middleware.RequestIDMiddleware",
    "identity.middleware.PrometheusMetricsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "profile_identity_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "profile_identity_project.wsgi.application"

if os.getenv("USE_SQLITE_FOR_TESTS", "False") == "True":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "test.sqlite3",
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME", "profile_identity"),
            "USER": os.getenv("DB_USER", "profile_identity"),
            "PASSWORD": os.getenv("DB_PASSWORD", "profile_identity"),
            "HOST": os.getenv("DB_HOST", "localhost"),
            "PORT": os.getenv("DB_PORT", "5434"),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "identity.User"

CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "True") == "True"
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:4200,http://127.0.0.1:4200,http://localhost:8082,http://127.0.0.1:8082",
    ).split(",")
    if origin.strip()
]

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_MINUTES", "15"))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.getenv("JWT_REFRESH_TOKEN_DAYS", "1"))),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": os.getenv("JWT_ALGORITHM", "HS256"),
    "SIGNING_KEY": JWT_SIGNING_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",
    "JTI_CLAIM": "jti",
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "EXCEPTION_HANDLER": "identity.exception_handlers.security_exception_handler",
}

LEGACY_SYNC_BASE_URL = os.getenv("LEGACY_SYNC_BASE_URL", "").rstrip("/")
LEGACY_SYNC_TOKEN = os.getenv("LEGACY_SYNC_TOKEN", "")
LEGACY_SYNC_ENABLED = os.getenv("LEGACY_SYNC_ENABLED", "False") == "True"
LEGACY_SYNC_RETRY_DELAY = timedelta(minutes=int(os.getenv("LEGACY_SYNC_RETRY_DELAY_MINUTES", "5")))

JWT_REFRESH_COOKIE_NAME = os.getenv("JWT_REFRESH_COOKIE_NAME", "centinela_refresh")
JWT_REFRESH_COOKIE_PATH = os.getenv("JWT_REFRESH_COOKIE_PATH", "/api")
JWT_REFRESH_COOKIE_DOMAIN = os.getenv("JWT_REFRESH_COOKIE_DOMAIN") or None
JWT_REFRESH_COOKIE_SECURE = os.getenv("JWT_REFRESH_COOKIE_SECURE", "False" if DEBUG else "True") == "True"
JWT_REFRESH_COOKIE_SAMESITE = os.getenv("JWT_REFRESH_COOKIE_SAMESITE", "Lax")
JWT_REFRESH_COOKIE_HTTPONLY = os.getenv("JWT_REFRESH_COOKIE_HTTPONLY", "True") == "True"
JWT_REFRESH_COOKIE_MAX_AGE = int(SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())

MFA_ENFORCEMENT_MODE = os.getenv("MFA_ENFORCEMENT_MODE", "enrollment_required")
MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "Centinela")
MFA_CHALLENGE_TTL_SECONDS = int(os.getenv("MFA_CHALLENGE_TTL_SECONDS", "300"))
MFA_TOTP_INTERVAL_SECONDS = int(os.getenv("MFA_TOTP_INTERVAL_SECONDS", "30"))
MFA_TOTP_VALID_WINDOW = int(os.getenv("MFA_TOTP_VALID_WINDOW", "1"))
MFA_CHALLENGE_MAX_FAILED_ATTEMPTS = int(os.getenv("MFA_CHALLENGE_MAX_FAILED_ATTEMPTS", "3"))
MFA_LOCKOUT_FAILURE_THRESHOLD = int(os.getenv("MFA_LOCKOUT_FAILURE_THRESHOLD", "5"))
MFA_LOCKOUT_MINUTES = [
    int(value.strip())
    for value in os.getenv("MFA_LOCKOUT_MINUTES", "5,15,30").split(",")
    if value.strip()
]
MFA_SECRET_ENCRYPTION_KEY = os.getenv("MFA_SECRET_ENCRYPTION_KEY", SECRET_KEY)

SECURITY_LOG_SERVICE_NAME = os.getenv("SECURITY_LOG_SERVICE_NAME", "identity-backend")
SECURITY_LOG_ENVIRONMENT = os.getenv("SECURITY_LOG_ENVIRONMENT", "dev")
SECURITY_LOG_INCLUDE_USERNAME = os.getenv("SECURITY_LOG_INCLUDE_USERNAME", "True" if DEBUG else "False") == "True"
DJANGO_ACCESS_LOGS_ENABLED = os.getenv("DJANGO_ACCESS_LOGS_ENABLED", "False") == "True"
METRICS_ENABLED = os.getenv("METRICS_ENABLED", "True") == "True"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {
            "format": "%(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "plain",
        },
        "null": {
            "class": "logging.NullHandler",
        },
    },
    "loggers": {
        "identity": {"handlers": ["console"], "level": "INFO", "propagate": True},
        "security.events": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.server": {
            "handlers": ["console"] if DJANGO_ACCESS_LOGS_ENABLED else ["null"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
