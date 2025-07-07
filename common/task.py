from celery import shared_task
from common.email_utils import EmailUtility, send_email

email_sender = EmailUtility()


@shared_task
def send_async_email(
    subject, recipient_list, message=None, html_message=None, from_email=None
):
    email_sender.send_email(
        subject=subject,
        html_message=html_message,
        message=message,
        recipient_list=recipient_list,
    )


@shared_task
def send_temp_password_email(email, temp_password):
    subject = "Your Temporary Password for GymOps"
    message = f"Hello,\n\nYour temporary password is: {temp_password}\nPlease log in and change it immediately.\n\nThank you!"
    send_email(subject, message, [email])


# @shared_task
# def send_async_sms(
#     subject, recipient_list, message=None, html_message=None, from_email=None
# ):
#     email_sender.send_email(
#         subject=subject,
#         html_message=html_message,
#         message=message,
#         recipient_list=recipient_list,
#     )
