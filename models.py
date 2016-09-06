from datetime import date, timedelta
from uuid import uuid4
from PIL import Image

from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager
)
from django.db.models import (
    BooleanField, CharField, DateField, DateTimeField, DecimalField,
    EmailField, ForeignKey, PositiveIntegerField, Model, Sum, TextField,
    ImageField
)

from core.country_codes import COUNTRY_CHOICES


class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(email=self.normalize_email(email))

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(email=email, password=password)
        user.is_admin = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser):
    """
    User model representing Renooit admins and Account Managers.

    Renooit admins are identified by the `is_admin` flag. Administrators at
    the VAR-level (or Account Owners) are identified by the `is_var_admin`
    flag.
    """
    is_active = BooleanField(default=True)
    is_admin = BooleanField(default=False)

    first_name = CharField(max_length=255, blank=True)
    last_name = CharField(max_length=255, blank=True)
    email = EmailField(max_length=255, unique=True)

    # Name of the VAR the user belongs to.
    var = ForeignKey(
        'Partner', related_name='managers', null=True, blank=True,
        verbose_name='Value-added Reseller'
    )
    is_var_admin = BooleanField(
        default=False, verbose_name='Is VAR admin?'
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'

    def __unicode__(self):
        return self.email

    def get_full_name(self):
        return u'%s %s' % (self.first_name, self.last_name)

    def get_short_name(self):
        return self.first_name

    @property
    def is_staff(self):
        return self.is_admin

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True


class Partner(Model):
    """
    Model representing a VAR (value-added reseller, or partner) with access to
    the RenooIT system.
    """
    name = CharField(max_length=255)

    address = CharField(max_length=511, blank=True)
    city = CharField(max_length=255, blank=True)
    state = CharField(max_length=255, blank=True)
    country = CharField(max_length=255, choices=COUNTRY_CHOICES)

    logo = ImageField(upload_to='vars', null=True, blank=True)

    class Meta:
        unique_together = ('name', 'country')

    def __unicode__(self):
        return self.name

    def save(self, *args, **kwargs):
        """
        Resize VAR's logo to be a 100x100 after saving.
        """
        super(Partner, self).save(*args, **kwargs)

        # Now check the logo dimensions, if there's one.
        if not self.logo:
            return

        old_width = self.logo.width
        old_height = self.logo.height
        new_width = 100
        new_height = 100

        # Only do this if the image needs resizing.
        if old_width > new_width or old_height > new_height:
            filename = str(self.logo.path)
            image = Image.open(filename)

            # Resize the image keeping the image's aspect ratio.
            if old_width > old_height:
                # Horizontal orientation.
                new_height = int(old_height * (float(new_width) / old_width))
            elif old_height > old_width:
                # Vertical orientation.
                new_width = int(old_width * (float(new_height) / old_height))

            image = image.resize((new_width, new_height), Image.ANTIALIAS)

            # Overwrite the image on the storage.
            image.save(filename)


class Customer(Model):
    """
    Model representing an end customer (i.e. a Juniper device owner), managed
    by an account manager.
    """
    business_name = CharField(max_length=255)
    email = EmailField(max_length=255)
    manager = ForeignKey('User', related_name='customers')

    address = CharField(max_length=511, blank=True)
    city = CharField(max_length=255, blank=True)
    state = CharField(max_length=255, blank=True)
    zip_code = CharField(max_length=255, blank=True)
    country = CharField(max_length=255, choices=COUNTRY_CHOICES)

    class Meta:
        unique_together = ('business_name', 'manager')

    def __unicode__(self):
        return self.business_name


class Location(Model):
    """
    Model representing a location where a Product may be in.
    """
    name = CharField(max_length=255)

    address = CharField(max_length=511, blank=True)
    city = CharField(max_length=255, blank=True)
    state = CharField(max_length=255, blank=True)
    zip_code = CharField(max_length=255, blank=True)
    country = CharField(max_length=255, choices=COUNTRY_CHOICES)

    customer = ForeignKey('Customer', related_name='locations')

    latitude = DecimalField(
        max_digits=10, decimal_places=7, null=True, blank=True, default=None
    )
    longitude = DecimalField(
        max_digits=10, decimal_places=7, null=True, blank=True, default=None
    )

    def __unicode__(self):
        return self.name


class Contract(Model):
    """
    Model representing a contract which may apply to multiple products.
    """
    number = CharField(max_length=255)
    service_sku = CharField(max_length=255)
    start_date = DateField()
    end_date = DateField()

    customer = ForeignKey('Customer', related_name='contracts')

    class Meta:
        unique_together = ('number', 'customer')

    def __unicode__(self):
        return self.number


class Product(Model):
    """
    Model representing a product (i.e. a device part), owned by a customer.
    """
    device_name = CharField(max_length=255, null=True, blank=True)
    model_number = CharField(max_length=255, blank=False)
    serial_number = CharField(max_length=255, null=True, blank=True)

    customer = ForeignKey('Customer', related_name='products')
    location = ForeignKey(
        'Location', related_name='products', null=True, blank=True
    )
    contract = ForeignKey(
        'Contract', related_name='products', null=True, blank=True
    )

    date_created = DateTimeField(auto_now_add=True)
    last_modified = DateTimeField(auto_now=True)

    def __unicode__(self):
        return u"{}".format(self.id)


class PriceList(Model):
    """
    Model representing a price list, composed of several `PriceListItem`s.
    """
    year = PositiveIntegerField()
    month = PositiveIntegerField()
    var = ForeignKey('Partner', related_name='pricelists')

    class Meta:
        unique_together = ('year', 'month', 'var')

    def __unicode__(self):
        return u"{}-{}".format(self.year, self.month)


class PriceListItem(Model):
    """
    Model representing an item of a price list.
    """
    price_list = ForeignKey('PriceList', related_name='items')

    model = CharField(max_length=255, blank=False)

    service_type = CharField(max_length=255, null=True, blank=True)
    material_type = CharField(max_length=255, null=True, blank=True)

    product_category = CharField(max_length=255, null=True, blank=True)
    product_family = CharField(max_length=255, null=True, blank=True)
    product_line = CharField(max_length=255, null=True, blank=True)

    short_description = CharField(max_length=255, null=True, blank=True)
    long_description = CharField(max_length=255, null=True, blank=True)

    lod_date = DateField(null=True, blank=True)

    # Prices for different country categories.
    cat1_price = PositiveIntegerField(null=True, blank=True)
    cat2_price = PositiveIntegerField(null=True, blank=True)
    cat3_price = PositiveIntegerField(null=True, blank=True)
    cat4_price = PositiveIntegerField(null=True, blank=True)

    date_created = DateTimeField(auto_now_add=True)
    last_modified = DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('price_list', 'model')

    def __unicode__(self):
        return self.model


class Opportunity(Model):
    IN_PROGRESS = 'in_progress'
    CLOSED_WON = 'closed_won'
    CLOSED_LOST = 'closed_lost'
    OPPORTUNITY_STATUS = (
        (IN_PROGRESS, 'In Progress'),
        (CLOSED_WON, 'Closed Won'),
        (CLOSED_LOST, 'Closed Lost'),
    )

    name = CharField(max_length=255)
    status = CharField(
        max_length=255,
        choices=OPPORTUNITY_STATUS,
        default=IN_PROGRESS
    )

    customer = ForeignKey('Customer', related_name='opportunities')
    author = ForeignKey('User', related_name='opportunities')

    creation_date = DateTimeField(auto_now_add=True)
    close_date = DateTimeField(null=True, blank=True)

    def __unicode__(self):
        return self.name


class Quote(Model):
    IN_PROGRESS = 'in_progress'
    SENT_TO_JUNIPER = 'sent_to_juniper'
    JUNIPER_QUOTE_UPLOADED = 'juniper_quote_uploaded'
    JUNIPER_QUOTE_VERIFIED = 'juniper_quote_verified'
    SENT_TO_DISTRIBUTOR = 'sent_to_distributor'
    COMPLETE = 'complete'
    QUOTE_STATUS = (
        (IN_PROGRESS, 'In Progress'),
        (SENT_TO_JUNIPER, 'Quote Sent to Juniper'),
        (JUNIPER_QUOTE_UPLOADED, 'Juniper Quote Uploaded'),
        (JUNIPER_QUOTE_VERIFIED, 'Juniper Quote Verified'),
        (SENT_TO_DISTRIBUTOR, 'Quote Sent to Distributor'),
        (COMPLETE, 'Complete/Uploaded'),
    )

    name = CharField(max_length=255)
    status = CharField(
        max_length=255,
        choices=QUOTE_STATUS,
        default=IN_PROGRESS
    )

    opportunity = ForeignKey('Opportunity', related_name='quotes')
    price_list = ForeignKey('PriceList', related_name='quotes')

    date_created = DateTimeField(auto_now_add=True)
    last_modified = DateTimeField(auto_now=True)
    expiration_date = DateField()

    customer_approved = BooleanField(default=True)
    version = PositiveIntegerField(default=1)

    # Numbers to track the quotes. Tracking number is automatically set, while
    # the reference number is manual and set by the user.
    tracking_number = CharField(max_length=255, default=uuid4)
    reference_number = CharField(max_length=255, null=True, blank=True)

    def __unicode__(self):
        return self.name

    def save(self, *args, **kwargs):
        # If it's being created and no expiration date has been set, set it to
        # 30 days into the future.
        if not self.pk and not self.expiration_date:
            self.expiration_date = date.today() + timedelta(days=30)
        super(Quote, self).save(*args, **kwargs)

    @property
    def total_price(self):
        return self.products.aggregate(Sum('price')).get('price__sum')

    def generate_contracts(self):
        """
        Returns a list of (unsaved) contracts for the associated ProductQuotes,
        along with the products that must be linked to each.
        """
        customer = self.opportunity.customer

        data = {}
        for product in self.products.all():
            if not product.plan:
                continue

            key = (product.plan, product.start_date, product.end_date)

            if key not in data:
                # Create the contract and add the current product.
                # TODO: Generate contract number; using tracking_number now.
                contract_number = self.tracking_number + '-' + str(len(data))
                contract = Contract(
                    number=contract_number,
                    service_sku=product.plan,
                    start_date=product.start_date,
                    end_date=product.end_date,
                    customer=customer,
                )
                data[key] = {
                    'contract': contract,
                    'products': [product.product],
                }
            else:
                # Add the current product only.
                data[key]['products'].append(product.product)

        return data.values()


class ProductQuote(Model):
    plan = CharField(max_length=255, null=True)
    price = DecimalField(max_digits=10, decimal_places=2)
    product = ForeignKey('Product', related_name='product_quotes')

    start_date = DateField(null=True)
    end_date = DateField(null=True)

    quote = ForeignKey('Quote', related_name='products')

    def __unicode__(self):
        return self.plan or 'no-plan'


class QuoteFeedback(Model):
    """
    Model to store feedback left on a quote by (unauthenticated) customers.
    """
    content = TextField()
    date_created = DateTimeField(auto_now_add=True)
    quote = ForeignKey('Quote', related_name='feedback')
