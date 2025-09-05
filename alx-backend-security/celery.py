import os
from celery import Celery
from __future__ import absolute_import, unicode_literals

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "alx-backend-security.settings")

app = Celery("alx-backend-security")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
