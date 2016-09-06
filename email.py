from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string


def send_welcome_email(user, credentials):
    context = {
        'user': user,
        'login_link': settings.FRONTEND_URL + '/app/login/',
        'credentials': credentials,
    }
    html_email = render_to_string('welcome_email.html', context)
    txt_email = render_to_string('welcome_email.txt', context)

    send_mail(
        "Welcome to RenooIT",
        txt_email,
        "noreply@renooit.com",
        [user.email],
        html_message=html_email
    )


def send_quote_email(customer, quote):
    quote_link = "{}/app/guest/quote/{}/".format(
        settings.FRONTEND_URL, quote.tracking_number
    )

    try:
        var = customer.manager.var
        logo = var.logo.url
    except (ValueError, AttributeError):
        # Default logo to display, if none is available.
        logo = '/static/renooit-logo.png'

    logo_full_url = '{}{}'.format(settings.BACKEND_URL, logo)

    context = {
        'customer': customer,
        'quote_link': quote_link,
        'logo': logo_full_url
    }

    html_email = render_to_string('quote_email.html', context)
    txt_email = render_to_string('quote_email.txt', context)

    send_mail(
        "RenooIT Quote",
        txt_email,
        "noreply@renooit.com",
        [customer.email],
        html_message=html_email
    )


def send_password_reset(user, token, uid):
    password_reset_link = "{}/app/passwordreset/{}/{}/".format(
        settings.FRONTEND_URL, uid, token
    )
    context = {
        'user': user,
        'password_reset_link': password_reset_link,
    }
    html_email = render_to_string('password_reset.html', context)
    txt_email = render_to_string('password_reset.txt', context)

    send_mail(
        "RenooIT Password Reset",
        txt_email,
        "noreply@renooit.com",
        [user.email],
        html_message=html_email
    )


def send_contact_form(sender, subject, message):
    context = {
        'sender': sender,
        'subject': subject,
        'message': message,
    }
    html_email = render_to_string('contact_form.html', context)
    txt_email = render_to_string('contact_form.html', context)

    send_mail(
        "Demo Schedule",
        txt_email,
        "noreply@renooit.com",
        ["support@renooit.com"],
        html_message=html_email
    )
