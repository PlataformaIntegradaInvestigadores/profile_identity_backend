# Generated for the controlled identity/profile migration.

import identity.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                ("id", models.CharField(default=identity.models.generate_unique_id, editable=False, max_length=10, primary_key=True, serialize=False)),
                ("password", models.CharField(max_length=128)),
                ("last_login", models.DateTimeField(blank=True, null=True, verbose_name="last login")),
                ("is_superuser", models.BooleanField(default=False)),
                ("first_name", models.CharField(max_length=30)),
                ("last_name", models.CharField(max_length=30)),
                ("username", models.EmailField(max_length=254, unique=True)),
                ("scopus_id", models.CharField(blank=True, max_length=20, null=True)),
                ("investigation_camp", models.CharField(blank=True, max_length=100, null=True)),
                ("institution", models.CharField(blank=True, max_length=100, null=True)),
                ("email_institution", models.EmailField(blank=True, max_length=254, null=True)),
                ("website", models.URLField(blank=True, null=True)),
                ("profile_picture", models.ImageField(blank=True, default="profile_pictures/default_profile_picture.png", null=True, upload_to=identity.models.get_profile_picture_filepath)),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False)),
                ("job_recommendations_embedding", models.JSONField(blank=True, null=True)),
                ("feed_recommendations_embedding", models.JSONField(blank=True, null=True)),
                ("profile_vector_updated_at", models.DateTimeField(blank=True, null=True)),
                ("interests", models.TextField(blank=True, null=True)),
                ("interaction_count", models.IntegerField(default=0)),
                ("groups", models.ManyToManyField(blank=True, related_name="profile_identity_user_set", to="auth.group", verbose_name="groups")),
                ("user_permissions", models.ManyToManyField(blank=True, related_name="profile_identity_user_set", to="auth.permission", verbose_name="user permissions")),
            ],
            options={"db_table": "users"},
        ),
        migrations.CreateModel(
            name="Group",
            fields=[
                ("id", models.CharField(default=identity.models.generate_unique_id, editable=False, max_length=10, primary_key=True, serialize=False)),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField()),
                ("voting_type", models.CharField(choices=[("Positional Voting", "Positional"), ("Non-Positional Voting", "Nonpositional")], default="Positional Voting", max_length=50)),
                ("admin", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="administered_groups", to="identity.user")),
            ],
            options={"db_table": "groups"},
        ),
        migrations.CreateModel(
            name="ProfileInformation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("about_me", models.TextField(blank=True, null=True)),
                ("disciplines", models.JSONField(blank=True, default=list)),
                ("contact_info", models.JSONField(blank=True, default=dict)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="profile_information", to="identity.user")),
            ],
            options={"db_table": "profiles_information"},
        ),
        migrations.CreateModel(
            name="GroupMembership",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("group", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="identity.group")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="identity.user")),
            ],
            options={"db_table": "group_users"},
        ),
        migrations.AddField(
            model_name="group",
            name="users",
            field=models.ManyToManyField(related_name="member_groups", through="identity.GroupMembership", to="identity.user"),
        ),
        migrations.AddConstraint(
            model_name="user",
            constraint=models.UniqueConstraint(condition=models.Q(("scopus_id__isnull", False)), fields=("scopus_id",), name="identity_unique_scopus_id"),
        ),
        migrations.AddConstraint(
            model_name="groupmembership",
            constraint=models.UniqueConstraint(fields=("group", "user"), name="identity_unique_group_user"),
        ),
    ]
