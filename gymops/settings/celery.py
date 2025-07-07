from __future__ import absolute_import, unicode_literals
import os
from celery import Celery, shared_task
from decouple import config

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", f'gymops.settings.{config("ENV", default="dev")}')

app = Celery('gymops')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Discover tasks in all registered Django app configs.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")

# @shared_task
# def send_temp_password_email(email, temp_password):
#     from django.core.mail import send_mail  # Import here, not at the top
#     send_mail(
#         'Your Temporary Password',
#         f'Your temporary password is: {temp_password}',
#         'no-reply@yourdomain.com',
#         [email],
#         fail_silently=False,
#     )
