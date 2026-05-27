# Generated for Semana 9 hardening: password login lockout

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("identity", "0005_usermfasettings_mfachallenge"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="failed_login_attempts",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="user",
            name="password_locked_until",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddIndex(
            model_name="user",
            index=models.Index(fields=["password_locked_until"], name="identity_pwd_locked_until"),
        ),
    ]
