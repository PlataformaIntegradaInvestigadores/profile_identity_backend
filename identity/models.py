import os
import random
import string
import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


def generate_unique_id(length=10):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def get_profile_picture_filepath(instance, filename):
    ext = filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join("profile_pictures/", filename)


class UserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("El campo Email debe ser establecido")
        email = self.normalize_email(username)
        user = self.model(username=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("El superusuario debe tener is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("El superusuario debe tener is_superuser=True.")
        return self.create_user(username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.CharField(max_length=10, primary_key=True, default=generate_unique_id, editable=False)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    username = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    scopus_id = models.CharField(max_length=20, null=True, blank=True)
    investigation_camp = models.CharField(max_length=100, null=True, blank=True)
    institution = models.CharField(max_length=100, null=True, blank=True)
    email_institution = models.EmailField(null=True, blank=True)
    website = models.URLField(max_length=200, null=True, blank=True)
    profile_picture = models.ImageField(
        upload_to=get_profile_picture_filepath,
        default="profile_pictures/default_profile_picture.png",
        null=True,
        blank=True,
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    job_recommendations_embedding = models.JSONField(null=True, blank=True)
    feed_recommendations_embedding = models.JSONField(null=True, blank=True)
    profile_vector_updated_at = models.DateTimeField(null=True, blank=True)
    interests = models.TextField(null=True, blank=True)
    interaction_count = models.IntegerField(default=0)

    groups = models.ManyToManyField(
        "auth.Group",
        verbose_name="groups",
        blank=True,
        related_name="profile_identity_user_set",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        verbose_name="user permissions",
        blank=True,
        related_name="profile_identity_user_set",
    )

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    def __str__(self):
        return self.username

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def save(self, *args, **kwargs):
        if self.scopus_id == "":
            self.scopus_id = None
        if not self.profile_picture:
            self.profile_picture = "profile_pictures/default_profile_picture.png"
        super().save(*args, **kwargs)

    class Meta:
        db_table = "users"
        constraints = [
            models.UniqueConstraint(
                fields=["scopus_id"],
                name="identity_unique_scopus_id",
                condition=models.Q(scopus_id__isnull=False),
            )
        ]


class ProfileInformation(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile_information")
    about_me = models.TextField(blank=True, null=True)
    disciplines = models.JSONField(default=list, blank=True)
    contact_info = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"{self.user.username}'s Profile Information"

    class Meta:
        db_table = "profiles_information"


class Group(models.Model):
    class VotingType(models.TextChoices):
        POSITIONAL = "Positional Voting"
        NONPOSITIONAL = "Non-Positional Voting"

    id = models.CharField(max_length=10, primary_key=True, default=generate_unique_id, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField()
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="administered_groups")
    users = models.ManyToManyField(User, through="GroupMembership", related_name="member_groups")
    voting_type = models.CharField(max_length=50, choices=VotingType.choices, default=VotingType.POSITIONAL)

    def __str__(self):
        return self.title

    class Meta:
        db_table = "groups"


class GroupMembership(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        db_table = "group_users"
        constraints = [
            models.UniqueConstraint(fields=["group", "user"], name="identity_unique_group_user")
        ]


class AuthSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="auth_sessions")
    refresh_jti = models.CharField(max_length=255, unique=True)
    refresh_token_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    rotation_count = models.PositiveIntegerField(default=0)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)

    @property
    def is_active(self):
        return self.revoked_at is None and self.expires_at > timezone.now()

    def revoke(self):
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at"])

    class Meta:
        db_table = "auth_sessions"
        indexes = [
            models.Index(fields=["user", "revoked_at"], name="identity_session_user_revoked"),
            models.Index(fields=["expires_at"], name="identity_session_expires_at"),
        ]


class LegacySyncOutbox(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.CharField(max_length=255)
    payload = models.JSONField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    next_retry_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "legacy_sync_outbox"
        indexes = [
            models.Index(fields=["status", "next_retry_at"], name="identity_outbox_status_retry"),
            models.Index(fields=["path", "status"], name="identity_outbox_path_status"),
        ]
