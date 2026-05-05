#!/usr/bin/env python
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "profile_identity_project.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("Django is not installed or is not on PYTHONPATH.") from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
