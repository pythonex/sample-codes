import requests

from datetime import datetime

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from rest_framework.serializers import (
    ModelSerializer, Serializer, CharField, ChoiceField, DateField,
    PrimaryKeyRelatedField, DecimalField, EmailField, SerializerMethodField,
)
from rest_framework.exceptions import ValidationError

from core.models import (
    Contract, Customer, Location, Partner, Product, User, PriceList,
    PriceListItem, Opportunity, ProductQuote, Quote, QuoteFeedback,
)
from core.email import send_password_reset, send_contact_form


class AuthTokenSerializer(Serializer):
    email = CharField()
    password = CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(email=email, password=password)

            if user:
                if not user.is_active:
                    msg = 'User account is disabled.'
                    raise ValidationError(msg)
            else:
                msg = 'Unable to log in with provided credentials.'
                raise ValidationError(msg)
        else:
            msg = 'Must include "email" and "password".'
            raise ValidationError(msg)

        attrs['user'] = user
        return attrs


class UserSerializer(ModelSerializer):
    var_name = CharField(source='var.name', read_only=True)
    var = PrimaryKeyRelatedField(
        queryset=Partner.objects.all(),
        required=False, allow_null=True
    )

    class Meta:
        model = User
        fields = (
            'id', 'first_name', 'last_name', 'email', 'var', 'is_var_admin',
            'password', 'is_admin', 'is_active', 'var_name', 'last_login',
        )
        extra_kwargs = {'password': {
            'write_only': True,
            'required': False,
            'allow_blank': True
        }}

    def clean_data(self, validated_data):
        """
        Performs further cleaning of the `validated_data` dictionary before
        using it on the `create` and `update` methods.
        """
        # Only allow setting the `is_admin` flag to admins. If we have no
        # request context and thus cannot determine whether the user is an
        # admin, don't allow modification either.
        request = self.context.get('request')
        if not request or not request.user.is_admin:
            validated_data.pop('is_admin', None)

        # Same thing for the `is_var_admin` and `is_active` flag.
        if not request or (not request.user.is_admin and
                           not request.user.is_var_admin):
            validated_data.pop('is_var_admin', None)
            validated_data.pop('is_active', None)

        # If the user is not an admin, set the VAR to the logged-in user's VAR,
        # as we cannot create users for different partners.
        if request and not request.user.is_admin:
            try:
                validated_data['var'] = request.user.var
            except AttributeError:
                # The user has no VAR (shouldn't happen normally).
                validated_data['var'] = None

        # If the user is an admin, remove its var.
        if validated_data.get('is_admin'):
            validated_data['var'] = None

        return validated_data

    def create(self, validated_data):
        validated_data = self.clean_data(validated_data)

        # Create the user normally, setting the password separately.
        password = validated_data.pop('password', '')

        user = User(**validated_data)
        user.set_password(password)
        user.save()

        return user

    def update(self, instance, validated_data):
        validated_data = self.clean_data(validated_data)
        password = validated_data.pop('password', None)

        # Do not allow changing a user's VAR.
        validated_data.pop('var', None)

        old_is_admin = instance.is_admin
        # Update the user normally, setting the password separately.
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        # Remove the VAR when the user is turned an admin.
        if instance.is_admin and not old_is_admin:
            instance.var = None

        instance.save()

        return instance


class CustomerSerializer(ModelSerializer):
    manager = PrimaryKeyRelatedField(queryset=User.objects.all())

    products = PrimaryKeyRelatedField(many=True, read_only=True)
    contracts = PrimaryKeyRelatedField(many=True, read_only=True)
    locations = PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = Customer

    def validate_manager(self, value):
        if 'request' in self.context:
            user = self.context['request'].user
            if value.pk == user.pk\
               or (user.is_var_admin and user.var.pk == value.var.pk)\
               or (user.is_admin):
                return value
            raise ValidationError("Manager doesn't exist.")
        else:
            raise ValidationError(
                "Cannot set manager without a request in the context."
            )


class PartnerSerializer(ModelSerializer):
    class Meta:
        model = Partner


class ProductSerializer(ModelSerializer):

    # Make related fields writeable.
    location = PrimaryKeyRelatedField(
        queryset=Location.objects.all(),
        required=False, allow_null=True
    )
    customer = PrimaryKeyRelatedField(queryset=Customer.objects.all())

    class Meta:
        model = Product

    def validate_customer(self, value):
        if 'request' in self.context:
            user = self.context['request'].user
            if value.manager.pk == user.pk\
               or (user.is_var_admin and user.var.pk == value.manager.var.pk)\
               or (user.is_admin):
                return value
            raise ValidationError("Customer doesn't exist.")
        else:
            raise ValidationError(
                "Cannot set customer without a request in the context."
            )

    def validate(self, data):
        # Make sure the Location's Customer is the same as the Products's.
        location = data.get('location')
        if not location and self.instance:
            location = self.instance.location

        customer = data.get('customer')
        if not customer and self.instance:
            customer = self.instance.customer

        if location and location.customer.pk != customer.pk:
            raise ValidationError("`location` doesn't belong to `customer`.")

        return data

    def update(self, instance, validated_data):
        validated_data.pop('customer')  # Don't allow changing the customer.
        return super(ProductSerializer, self).update(instance, validated_data)


class ContractSerializer(ModelSerializer):
    products = PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = Contract

    def validate_customer(self, value):
        if 'request' in self.context:
            user = self.context['request'].user
            if not (value.manager.pk == user.pk or
                    (user.is_var_admin and
                     user.var.pk == value.manager.var.pk) or
                    (user.is_admin)):
                raise ValidationError("Customer doesn't exist.")

            # A contract may have multiple products. All of them should be the
            # value of `customer`.
            products = self.instance.products.all() if self.instance else []
            product_customers = list(set([p.customer.pk for p in products]))
            if len(product_customers) > 1:
                # Shouldn't happen, means something is wrong with the Products.
                raise ValidationError(
                    "Products have more than one customer. "
                    "This means the data is inconsistent"
                )

            if product_customers and value.pk != product_customers[0]:
                raise ValidationError(
                    "`customer` isn't `products`'s customer."
                )

        else:
            raise ValidationError(
                "Cannot set customer without a request in the context."
            )

        return value

    def update(self, instance, validated_data):
        validated_data.pop('customer')  # Don't allow changing the customer.
        return super(ContractSerializer, self).update(instance, validated_data)


class LocationSerializer(ModelSerializer):
    products = PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        many=True, required=False
    )
    customer = PrimaryKeyRelatedField(queryset=Customer.objects.all())

    class Meta:
        model = Location

    def validate_customer(self, value):
        if 'request' in self.context:
            user = self.context['request'].user
            if not (value.manager.pk == user.pk or
                    (user.is_var_admin and
                     user.var.pk == value.manager.var.pk) or
                    (user.is_admin)):
                raise ValidationError("Customer doesn't exist.")

            # A location may have multiple products. All of them should be the
            # value of `customer`.
            products = self.instance.products.all() if self.instance else []
            product_customers = list(set([p.customer.pk for p in products]))
            if len(product_customers) > 1:
                # Shouldn't happen, means something is wrong with the Products.
                raise ValidationError(
                    "Products have more than one customer. "
                    "This means the data is inconsistent"
                )

            if product_customers and value.pk != product_customers[0]:
                raise ValidationError(
                    "`customer` isn't `products`'s customer."
                )

        else:
            raise ValidationError(
                "Cannot set customer without a request in the context."
            )

        return value

    def validate(self, data):
        # Make sure the Location's Customer is the same as the Product'.
        products = data.get('products') or []
        not_owned = [
            p for p in products
            if p.customer.pk != self.instance.customer.pk
        ]

        if not_owned:
            ids = [p.id for p in not_owned]
            raise ValidationError(
                "Invalid pks `{}` - objects do not exist.".format(ids)
            )

        return data

    def update(self, instance, validated_data):
        validated_data.pop('customer')  # Don't allow changing the customer.
        return super(LocationSerializer, self).update(instance, validated_data)


class PriceListItemSerializer(ModelSerializer):

    class Meta:
        model = PriceListItem
        exclude = ('price_list',)


class PriceListSerializer(ModelSerializer):
    var_name = CharField(source='var.name', read_only=True)
    items = PriceListItemSerializer(many=True)

    class Meta:
        model = PriceList


class SummaryPriceListSerializer(ModelSerializer):
    var_name = CharField(source='var.name', read_only=True)

    class Meta:
        model = PriceList


class GenerateQuoteSerializer(Serializer):
    SUPPORT_TYPES = ['COR', 'CP', 'ND', 'NDS', 'SD', 'NDCE', 'SDCE']
    SUPPORT_PERIODS = [0, 1, 3, 5]

    name = CharField()
    opportunity = PrimaryKeyRelatedField(
        queryset=Opportunity.objects.all()
    )
    products = PrimaryKeyRelatedField(
        many=True, queryset=Product.objects.all()
    )
    price_list = PrimaryKeyRelatedField(queryset=PriceList.objects.all())
    support_type = ChoiceField(choices=SUPPORT_TYPES)
    support_period = ChoiceField(choices=SUPPORT_PERIODS)
    coterminus_date = DateField(required=False)
    reference_date = DateField(required=False)
    expiration_date = DateField(required=False)

    def validate_opportunity(self, value):
        # Make sure the opportunity referenced exists and is accessible by the
        # user.
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if user.is_var_admin and value.author.var != user.var:
            raise ValidationError("`opportunity` does not exist.")
        elif not user.is_admin and value.author.pk != user.pk:
            raise ValidationError("`opportunity` does not exist.")

        return value

    def validate_price_list(self, value):
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if not user.var:
            raise ValidationError(
                "You must have a VAR associated to create a quote."
            )

        if user.var.pk != value.var.pk:
            raise ValidationError("`price_list` does not exist.")

        return value

    def validate(self, attrs):
        support_period = attrs.get('support_period')
        coterminus_date = attrs.get('coterminus_date')
        if support_period != 0 and coterminus_date:
            raise ValidationError(
                "`coterminus_date` is only allowed if `support_period` is `0`."
            )

        # Make sure the products referenced exist and are accessible by the
        # user, and that they belong to the customer.
        products = attrs.get('products')
        customer = attrs.get('opportunity').customer
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if user.is_admin:
            qs = Product.objects.filter(customer=customer)
        elif user.is_var_admin:
            qs = Product.objects.filter(
                customer__manager__var=user.var,
                customer=customer
            )
        else:
            qs = Product.objects.filter(
                customer__manager=user,
                customer=customer
            )

        product_ids = [p.id for p in products]
        products = qs.in_bulk(product_ids)

        if len(products.keys()) < len(product_ids):
            missing = list(set(product_ids) - set(products.keys()))
            raise ValidationError(
                "Invalid pks `{}` - objects do not exist or do not belong to "
                "the customer.".format(missing)
            )

        return attrs


class AddProductsToQuoteSerializer(Serializer):
    SUPPORT_TYPES = ['COR', 'CP', 'ND', 'NDS', 'SD', 'NDCE', 'SDCE']
    SUPPORT_PERIODS = [0, 1, 3, 5]

    quote = PrimaryKeyRelatedField(queryset=Quote.objects.all())
    products = PrimaryKeyRelatedField(
        many=True, queryset=Product.objects.all()
    )
    support_type = ChoiceField(choices=SUPPORT_TYPES)
    support_period = ChoiceField(choices=SUPPORT_PERIODS)
    coterminus_date = DateField(required=False)
    reference_date = DateField(required=False)

    def validate_quote(self, value):
        # Make sure the quote referenced exists and is accessible by the
        # user.
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if value.opportunity.author.pk != user.pk:
            raise ValidationError("`quote` does not exist.")

        return value

    def validate(self, attrs):
        quote = attrs.get('quote')
        support_period = attrs.get('support_period')
        coterminus_date = attrs.get('coterminus_date')
        if support_period != 0 and coterminus_date:
            raise ValidationError(
                "`coterminus_date` is only allowed if `support_period` is `0`."
            )

        # Make sure the products referenced exist and are accessible by the
        # user, and that they belong to the customer.
        products = attrs.get('products')
        customer = attrs.get('quote').opportunity.customer
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if user.is_admin:
            qs = Product.objects.filter(customer=customer)
        elif user.is_var_admin:
            qs = Product.objects.filter(
                customer__manager__var=user.var,
                customer=customer
            )
        else:
            qs = Product.objects.filter(
                customer__manager=user,
                customer=customer
            )

        # Don't include products already in the quote.
        qs = qs.exclude(product_quotes__quote=quote)

        product_ids = [p.id for p in products]
        products = qs.in_bulk(product_ids)

        if len(products.keys()) < len(product_ids):
            missing = list(set(product_ids) - set(products.keys()))
            raise ValidationError(
                "Invalid pks `{}` - objects do not exist or do not belong to "
                "the customer.".format(missing)
            )

        return attrs


class RemoveProductsFromQuoteSerializer(Serializer):
    quote = PrimaryKeyRelatedField(queryset=Quote.objects.all())
    products = PrimaryKeyRelatedField(
        many=True, queryset=ProductQuote.objects.all()
    )

    def validate_quote(self, value):
        # Make sure the quote referenced exists and is accessible by the
        # user.
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if value.opportunity.author.pk != user.pk:
            raise ValidationError("`quote` does not exist.")

        return value

    def validate(self, attrs):
        quote = attrs.get('quote')
        products = attrs.get('products')

        product_ids = [p.id for p in products]
        products = quote.products.in_bulk(product_ids)

        if len(products.keys()) < len(product_ids):
            missing = list(set(product_ids) - set(products.keys()))
            raise ValidationError(
                "Invalid pks `{}` - objects do not exist or do not belong to "
                "the customer.".format(missing)
            )

        return attrs


class QuoteFeedbackSerializer(ModelSerializer):
    class Meta:
        model = QuoteFeedback
        read_only_fields = ('date_created', 'quote',)


class ProductQuoteSerializer(ModelSerializer):
    class Meta:
        model = ProductQuote
        read_only_fields = ('product', 'quote',)


class QuoteSerializer(ModelSerializer):
    expiration_date = DateField(required=False)

    products = ProductQuoteSerializer(many=True)
    total_price = DecimalField(max_digits=10, decimal_places=2)
    feedback = QuoteFeedbackSerializer(many=True)

    class Meta:
        model = Quote
        read_only_fields = (
            'opportunity', 'date_created', 'last_modified', 'products',
            'total_price', 'tracking_number', 'feedback',
        )


class QuoteUpdateSerializer(ModelSerializer):
    class Meta:
        model = Quote
        fields = (
            'name', 'status', 'expiration_date', 'customer_approved',
            'version', 'tracking_number', 'reference_number', 'price_list'
        )


class OpportunitySerializer(ModelSerializer):
    quotes = QuoteSerializer(many=True, read_only=True)

    class Meta:
        model = Opportunity
        read_only_fields = ('creation_date', 'close_date',)

    def validate_author(self, value):
        # Make sure the user is either the logged in one or under the
        # supervision of the logged in person.
        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")
        user = self.context['request'].user

        if user.is_var_admin and user.var != value.var:
            raise ValidationError("User not found.")
        elif not user.is_var_admin and not user.is_admin and user != value:
            raise ValidationError("User not found.")

        return value

    def validate(self, data):
        # Don't allow modifying the author once a quote exists on the
        # opportunity.
        if self.instance and self.instance.quotes.exists():
            if self.instance.author != data.get('author'):
                raise ValidationError(
                    "`author` may not be modified while a Quote exists."
                )
            if self.instance.customer != data.get('customer'):
                raise ValidationError(
                    "`customer` may not be modified while a Quote exists."
                )

        if data.get('customer').manager != data.get('author'):
            raise ValidationError("`customer` doesn't belong to `author`.")

        return data

    def update(self, instance, validated_data):
        # Set the close date if necessary.
        new_status = validated_data.get('status')
        status_changed = new_status != instance.status
        if status_changed and new_status != Opportunity.IN_PROGRESS:
            validated_data['close_date'] = datetime.utcnow()

        return super(OpportunitySerializer, self).update(
            instance, validated_data
        )

    def create(self, validated_data):
        # Set the close date if necessary.
        status = validated_data.get('status')
        if status != Opportunity.IN_PROGRESS:
            validated_data['close_date'] = datetime.utcnow()

        return super(OpportunitySerializer, self).create(validated_data)


class GuestProductSerializer(ModelSerializer):
    """
    Full serializer for the guest view of the quotes.
    """
    location = SerializerMethodField()

    class Meta:
        model = Product
        exclude = ('contract', 'date_created', 'last_modified',)

    def get_location(self, obj):
        return obj.location.name if obj.location else None


class GuestProductQuoteSerializer(ModelSerializer):
    """
    Full serializer for the guest view of the quotes.
    """
    product = GuestProductSerializer(read_only=True)

    class Meta:
        model = ProductQuote
        exclude = ('quote',)


class GuestQuoteSerializer(ModelSerializer):
    """
    Full serializer for the guest view of the quotes.
    """
    expiration_date = DateField(read_only=True)
    products = GuestProductQuoteSerializer(many=True, read_only=True)
    total_price = DecimalField(max_digits=10, decimal_places=2, read_only=True)
    feedback = QuoteFeedbackSerializer(many=True, read_only=True)

    class Meta:
        model = Quote
        depth = 1
        # Only `customer_approved` is writable.
        read_only_fields = (
            'name', 'status', 'opportunity', 'date_created', 'last_modified',
            'expiration_date', 'version', 'tracking_number',
            'reference_number',
        )


class PasswordResetSerializer(Serializer):
    email = EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
            return value
        except User.DoesNotExist:
            raise ValidationError("No user with that email.")

    def save(self, **kwargs):
        """
        Generate the token and email it to the user.
        """
        user = User.objects.get(email=self.validated_data['email'])
        # A one-use token to reset the password
        token = default_token_generator.make_token(user)
        # The user ID, to identify the user on the email.
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        send_password_reset(user, token, uid)


class PasswordResetConfirmSerializer(Serializer):
    uid = CharField()
    token = CharField()
    password = CharField(allow_blank=False)

    def validate_uid(self, value):
        try:
            uid = force_text(urlsafe_base64_decode(value))
            User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise ValidationError("Invalid uid.")

        return value

    def validate(self, data):
        # Has already been validated; it's safe to decode.
        uid = force_text(urlsafe_base64_decode(data['uid']))
        user = User.objects.get(pk=uid)

        # Validate the token received.
        token = data['token']
        if default_token_generator.check_token(user, token):
            return data
        else:
            raise ValidationError("Invalid token.")

    def save(self, **kwargs):
        uid = force_text(urlsafe_base64_decode(self.validated_data['uid']))
        user = User.objects.get(pk=uid)

        user.set_password(self.validated_data['password'])
        user.save()


class ContactFormSerializer(Serializer):
    full_name = CharField(allow_blank=False)
    email = EmailField(allow_blank=False)
    subject = CharField(allow_blank=False)
    message = CharField(allow_blank=False)
    captcha = CharField(allow_blank=False)

    def validate_captcha(self, value):
        if not settings.CAPTCHA_SECRET:
            # If not present, don't check.
            return value

        if 'request' not in self.context:
            raise ValidationError("Request must be present in context.")

        remote_ip = self.context['request'].META.get(settings.REMOTE_IP_HEADER)
        if not remote_ip:
            raise ValidationError("Couldn't get remote IP address.")

        endpoint = "https://www.google.com/recaptcha/api/siteverify"
        params = {
            'secret': settings.CAPTCHA_SECRET,
            'response': value,
            'remoteip': remote_ip,
        }

        try:
            response = requests.get(endpoint, params=params).json()
        except:
            raise ValidationError("Error contacting reCAPTCHA API.")

        if not response['success']:
            raise ValidationError("Challenge response invalid.")

        return value

    def save(self, **kwargs):
        sender = {
            'full_name': self.validated_data['full_name'],
            'email': self.validated_data['email'],
        }
        if self.validated_data['subject'] == 'support':
            subject = 'Schedule a Demo'
        else:
            subject = 'Other'
        message = self.validated_data['message']

        send_contact_form(sender, subject, message)
