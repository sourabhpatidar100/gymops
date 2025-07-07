from django.core.mail import send_mail
import logging
from common.meta.design_pattern import SingletonMeta
from django.conf import settings


class EmailUtility(metaclass=SingletonMeta):
    """
    Singleton utility class for sending emails.
    """

    def __init__(self, default_from_email="no-reply@yourdomain.com"):
        self.default_from_email = default_from_email
        self.logger = logging.getLogger(__name__)

    def send_email(
        self, subject, message, recipient_list, html_message=None, from_email=None
    ):
        """
        Sends an email to the specified recipient list.

        Args:
            subject (str): The subject of the email.
            message (str): The email content.
            recipient_list (list): List of recipient email addresses.
            html_message (str, optional): HTML version of the email content.
            from_email (str, optional): The sender's email address. Defaults to `default_from_email`.

        Raises:
            Exception: If the email sending fails.
        """
        try:
            # Use the provided from_email or fallback to the default
            from_email = from_email or self.default_from_email

            send_mail(
                subject=subject,
                message=message,
                html_message=html_message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False,
            )
        except Exception as e:
            # Log the exception with traceback for better debugging
            self.logger.error("Failed to send email", exc_info=True)
            raise Exception("Email sending failed. Please try again later.") from e





def send_email(subject, message, recipient_list):
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        fail_silently=False,
    )
