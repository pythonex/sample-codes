from datetime import datetime
from decimal import Decimal
from structlog import get_logger

from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist

from django_filters import FilterSet, MethodFilter

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken as StockTokenView
from rest_framework.decorators import detail_route
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from core.models import (
    Contract, Customer, Location, Partner, ProductQuote, PriceList,
    PriceListItem, Product, Quote, User, Opportunity,
)
from core.email import send_quote_email, send_welcome_email
from core.parsing import get_support_products, get_products
from core.permissions import (
    IsUnauthenticated, IsPrivilegedUser, IsVarAdminUser,
)
from core.quote import generate_quote as generate_quote_function
from core.quote.report import generate_report
from core.quote.countries import get_country_category
from core.mixins import (
    DestroyModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin,
    ModelViewSet
)
from core.serializers import (
    AuthTokenSerializer, ContractSerializer, CustomerSerializer,
    ProductSerializer, GenerateQuoteSerializer, LocationSerializer,
    PartnerSerializer, UserSerializer, PriceListSerializer,
    SummaryPriceListSerializer, QuoteSerializer, ProductQuoteSerializer,
    OpportunitySerializer, GuestQuoteSerializer, QuoteFeedbackSerializer,
    QuoteUpdateSerializer, AddProductsToQuoteSerializer,
    RemoveProductsFromQuoteSerializer, PasswordResetSerializer,
    PasswordResetConfirmSerializer, ContactFormSerializer,
)


log = get_logger('renooit')


class LoginView(StockTokenView):
    """
    View to obtain an authentication token for the user.

    We offer both SessionAuthentication and TokenAuthentication, which allows
    us to seamlessly use the browsable API.
    """
    permission_classes = (IsUnauthenticated,)
    serializer_class = AuthTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        log.info('user.login', user=user.id)

        user.last_login = datetime.utcnow()
        user.save(update_fields=['last_login'])

        return Response({'token': token.key})

login = LoginView.as_view()


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        return self.do_logout(request)

    def get(self, request):
        return self.do_logout(request)

    def do_logout(self, request):
        # Delete any authentication token associated to the user.
        Token.objects.filter(user=request.user).delete()
        log.info('user.logout', user=request.user.id)
        return Response({'token': None})

logout = LogoutView.as_view()


class ProfileViewSet(RetrieveModelMixin, UpdateModelMixin, GenericViewSet):
    """
    ViewSet tasked with displaying the logged-in user's profile.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

user_profile = ProfileViewSet.as_view({
    'get': 'retrieve',
    'patch': 'update',
    'put': 'update'
})


class CustomerViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = CustomerSerializer
    filter_fields = ('manager', 'products',)

    def get_queryset(self):
        """
        Returns the customers associated with the logged-in user.

        If the authenticated user is a VAR admin, allow listing *all* the
        customers for his VAR.
        """
        if self.request.user.is_admin:
            qs = Customer.objects.all()
        elif self.request.user.is_var_admin:
            qs = Customer.objects.filter(manager__var=self.request.user.var)
        else:
            qs = self.request.user.customers

        return qs


class UserViewSet(ModelViewSet):
    """
    ViewSet tasked with user management.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer
    filter_fields = ('var',)

    def get_queryset(self):
        """
        Returns only users from the same VAR, in the case of VAR admins.
        """
        if self.request.user.is_var_admin:
            qs = User.objects.filter(var=self.request.user.var)
        elif self.request.user.is_admin:
            qs = User.objects.all()
        else:
            qs = User.objects.filter(id=self.request.user.id)

        if self.action == 'destroy' and not self.request.user.is_admin:
            # Don't let non-admins delete admins.
            qs = qs.filter(is_admin=False)

        return qs

    def perform_create(self, serializer):
        credentials = {
            'email': serializer.validated_data.get('email'),
            'password': serializer.validated_data.get('password'),
        }
        super(UserViewSet, self).perform_create(serializer)
        send_welcome_email(serializer.instance, credentials)


class ImportPriceListView(APIView):
    permission_classes = (IsAuthenticated, IsVarAdminUser,)

    def post(self, request):
        price_list = request.data.get('price_list')
        if not price_list:
            raise ValidationError("`price_list` is required.")

        try:
            data = get_support_products(price_list.read())
        except ValueError:
            raise ValidationError("Invalid price list file.")

        # Check if the price list was already stored on the database.
        price_list, just_created = PriceList.objects.get_or_create(
            year=data['year'],
            month=data['month'],
            var=self.request.user.var,
        )

        # Delete all the items and recreate them. This will delete items even
        # if they are not in the new price list.
        if not just_created:
            price_list.items.all().delete()

        # Create all `PriceListItem`s at once.
        objs = []
        for item in data['items']:
            item['price_list_id'] = price_list.id
            objs.append(PriceListItem(**item))
        PriceListItem.objects.bulk_create(objs)

        result = PriceListSerializer(instance=price_list).data

        log.info(
            'pricelist.import',
            user=self.request.user.pk,
            object=price_list.pk
        )

        return Response(result)

import_price_list = ImportPriceListView.as_view()


class PriceListView(DestroyModelMixin, ListModelMixin, RetrieveModelMixin,
                    GenericViewSet):
    serializer_class = PriceListSerializer

    def get_queryset(self):
        if self.request.user.var:
            qs = PriceList.objects.filter(var=self.request.user.var)
        elif self.request.user.is_admin:
            qs = PriceList.objects.all()
        else:
            qs = PriceList.objects.none()
        return qs

    def get_permission_classes(self):
        if self.action == 'delete':
            return (IsAuthenticated, IsVarAdminUser,)
        else:
            return (IsAuthenticated,)

    def get_serializer_class(self):
        # We don't want to display all the items when displaying the list of
        # available price lists.
        if self.action == 'list':
            return SummaryPriceListSerializer
        else:
            return PriceListSerializer

single_price_list = PriceListView.as_view({
    'get': 'retrieve',
    'delete': 'destroy'
})
multiple_price_list = PriceListView.as_view({'get': 'list'})


class ImportInventoryView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        inventory = request.data.get('inventory')
        if not inventory:
            raise ValidationError("`inventory` is required.")

        try:
            data = get_products(inventory)
        except:
            # The csv module may raise any type of exception.
            raise ValidationError("Invalid inventory file.")

        # Store the data from the inventory file.
        customer = self.get_customer()
        new_contracts = self.create_contracts(data['contracts'], customer)
        new_locations = self.create_locations(data['locations'], customer)
        new_products = self.create_products(data['products'], customer)

        log.info(
            'inventory.import',
            user=self.request.user.pk,
            customer=customer.pk
        )

        result = {
            'new_contracts': ContractSerializer(new_contracts, many=True).data,
            'new_locations': LocationSerializer(new_locations, many=True).data,
            'new_products': ProductSerializer(new_products, many=True).data,
        }

        return Response(result)

    def get_queryset(self):
        if self.request.user.is_admin:
            qs = Customer.objects.all()
        elif self.request.user.is_var_admin:
            qs = Customer.objects.filter(manager__var=self.request.user.var)
        else:
            qs = Customer.objects.filter(manager=self.request.user)

        return qs

    def get_customer(self):
        """
        Retrieves the customer pointed by `customer_id`, as long as the logged
        in user is allowed to see it.
        """
        customer_id = self.request.data.get('customer')
        if not customer_id:
            raise ValidationError("`customer` is required.")

        try:
            customer = self.get_queryset().get(pk=customer_id)
        except Customer.DoesNotExist:
            raise ValidationError("`customer` does not exist.")

        return customer

    def create_contracts(self, contracts, customer):
        """
        Creates the new contracts needed.
        """
        if not contracts:
            return []

        contract_numbers = [c['number'] for c in contracts]
        existing_contracts = Contract.objects.filter(
            number__in=contract_numbers, customer=customer
        )
        existing_numbers = [c.number for c in existing_contracts]
        missing = set(contract_numbers) - set(existing_numbers)

        new_contracts = list(existing_contracts)
        for contract in contracts:
            if contract['number'] not in missing:
                continue
            contract['customer_id'] = customer.id
            new_contracts.append(Contract.objects.create(**contract))

        return new_contracts

    def create_locations(self, locations, customer):
        """
        Creates the new locations needed.
        """
        if not locations:
            return []

        new_locations = []
        for location in locations:
            obj, _ = Location.objects.get_or_create(
                name=location.get('name'),
                address=location.get('address'),
                city=location.get('city'),
                state=location.get('state'),
                zip_code=location.get('zip_code'),
                country=location.get('country'),
                customer=customer
            )
            new_locations.append(obj)

        return new_locations

    def create_products(self, products, customer):
        """
        Creates the new products, making sure they're not being created twice.
        """
        new_products = []

        for product in products:
            identifier = {}
            additional_data = {}

            # Basic, identifying, product information.
            identifier['device_name'] = product.get('device_name')
            identifier['model_number'] = product.get('model_number')
            identifier['serial_number'] = product.get('serial_number')
            identifier['customer_id'] = customer.id

            # Get the contract information.
            contract_number = product.pop('contract_number', None)
            if contract_number:
                contract = Contract.objects.get(
                    number=contract_number,
                    customer=customer
                )
                additional_data['contract_id'] = contract.id

            # Get the location information, if available.
            location = product.pop('location', None)
            if location:
                l = Location.objects.get(customer=customer, **location)
                additional_data['location_id'] = l.id

            new_product, _ = Product.objects.update_or_create(
                defaults=additional_data, **identifier
            )
            new_products.append(new_product)

        return new_products

import_inventory = ImportInventoryView.as_view()


class ProductFilterSet(FilterSet):
    """
    Filtering definitions for Product viewsets.

    Defined explicitly to provide non-trivial filtering functionalities.
    """
    not_in_quote = MethodFilter(action='filter_not_in_quote')

    class Meta:
        model = Product
        fields = [
            'model_number', 'serial_number', 'device_name', 'customer',
            'location', 'product_quotes__quote'
        ]

    def filter_not_in_quote(self, queryset, value):
        return queryset.exclude(product_quotes__quote__id=value)


class ProductViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProductSerializer
    filter_class = ProductFilterSet

    def get_queryset(self):
        if self.request.user.is_admin:
            qs = Product.objects.all()
        elif self.request.user.is_var_admin:
            qs = Product.objects.filter(
                customer__manager__var=self.request.user.var
            )
        else:
            qs = Product.objects.filter(
                customer__manager=self.request.user
            )

        return qs


class ContractViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = ContractSerializer
    filter_fields = {
        'customer': ['exact'],
        'products': ['exact'],
        'start_date': ['exact', 'lte', 'gte'],
        'end_date': ['exact', 'lte', 'gte'],
    }

    def get_queryset(self):
        if self.request.user.is_admin:
            qs = Contract.objects.all()
        elif self.request.user.is_var_admin:
            qs = Contract.objects.filter(
                customer__manager__var=self.request.user.var
            ).distinct()
        else:
            qs = Contract.objects.filter(
                customer__manager=self.request.user
            ).distinct()

        return qs


class LocationViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = LocationSerializer
    filter_fields = ('customer', 'products',)

    def get_queryset(self):
        if self.request.user.is_admin:
            qs = Location.objects.all()
        elif self.request.user.is_var_admin:
            qs = Location.objects.filter(
                customer__manager__var=self.request.user.var
            )
        else:
            qs = Location.objects.filter(
                customer__manager=self.request.user
            )

        return qs


class PartnerViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated, IsPrivilegedUser,)
    serializer_class = PartnerSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            qs = Partner.objects.all()
        elif user.is_var_admin:
            qs = Partner.objects.filter(id=user.var.pk)
        else:
            qs = Partner.objects.none()

        return qs


class GenerateQuoteView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = GenerateQuoteSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        quote_data = generate_quote_function(
            serializer.validated_data.get('price_list'),
            serializer.validated_data.get('products'),
            serializer.validated_data.get('support_type'),
            serializer.validated_data.get('support_period'),
            serializer.validated_data.get('coterminus_date'),
            serializer.validated_data.get('reference_date'),
        )

        # Store the quote.
        qdict = {
            'name': serializer.validated_data.get('name'),
            'opportunity': serializer.validated_data.get('opportunity'),
            'price_list': serializer.validated_data.get('price_list'),
        }

        expiration = serializer.validated_data.get('expiration_date')
        if expiration:
            qdict['expiration_date'] = expiration

        quote = Quote.objects.create(**qdict)

        for product in quote_data['products']:
            ProductQuote.objects.create(
                quote=quote,
                plan=product['plan'],
                price=product['price'],
                product_id=product['product'],
                start_date=product['start_date'],
                end_date=product['end_date'],
            )

        log.info(
            'quote.generate',
            object=quote.id,
            opportunity=quote.opportunity.id,
            user=self.request.user.pk
        )

        return Response(QuoteSerializer(instance=quote).data)

generate_quote = GenerateQuoteView.as_view()


class AddProductsToQuoteView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = AddProductsToQuoteSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        quote = serializer.validated_data.get('quote')

        quote_data = generate_quote_function(
            quote.price_list,
            serializer.validated_data.get('products'),
            serializer.validated_data.get('support_type'),
            serializer.validated_data.get('support_period'),
            serializer.validated_data.get('coterminus_date'),
            serializer.validated_data.get('reference_date'),
        )

        for product in quote_data['products']:
            ProductQuote.objects.create(
                quote=quote,
                plan=product['plan'],
                price=product['price'],
                product_id=product['product'],
                start_date=product['start_date'],
                end_date=product['end_date'],
            )

        # Update the quote's version.
        quote.version += 1
        quote.save()

        log.info(
            'quote.addproducts',
            object=quote.id,
            opportunity=quote.opportunity.id,
            user=self.request.user.pk
        )

        return Response(QuoteSerializer(instance=quote).data)

add_products_to_quote = AddProductsToQuoteView.as_view()


class RemoveProductsFromQuoteView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = RemoveProductsFromQuoteSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        quote = serializer.validated_data.get('quote')

        products = serializer.validated_data.get('products')
        product_ids = [p.id for p in products]

        ProductQuote.objects.filter(id__in=product_ids).delete()

        # Update the quote's version.
        quote.version += 1
        quote.save()

        log.info(
            'quote.removeproducts',
            object=quote.id,
            opportunity=quote.opportunity.id,
            user=self.request.user.pk
        )

        return Response(QuoteSerializer(instance=quote).data)

remove_products_from_quote = RemoveProductsFromQuoteView.as_view()


class OpportunityViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = OpportunitySerializer
    filter_fields = ('customer',)

    def get_queryset(self):
        if self.request.user.is_admin:
            qs = Opportunity.objects.all()
        elif self.request.user.is_var_admin:
            qs = Opportunity.objects.filter(author__var=self.request.user.var)
        else:
            qs = Opportunity.objects.filter(author=self.request.user)

        return qs


class QuoteViewSet(RetrieveModelMixin, UpdateModelMixin, ListModelMixin,
                   DestroyModelMixin, GenericViewSet):
    permission_classes = (IsAuthenticated,)
    filter_fields = ('products__product',)

    def get_queryset(self):
        if self.request.user.is_admin:
            qs = Quote.objects.all()
        elif self.request.user.is_var_admin:
            qs = Quote.objects.filter(
                opportunity__author__var=self.request.user.var
            )
        else:
            qs = Quote.objects.filter(opportunity__author=self.request.user)

        return qs

    def get_serializer_class(self):
        if self.action in ['create', 'update']:
            return QuoteUpdateSerializer
        else:
            return QuoteSerializer

    def update(self, request, pk=None):
        initial_price_list = self.get_object().price_list

        super(QuoteViewSet, self).update(request, pk)

        quote = self.get_object()
        actual_price_list = quote.price_list
        if initial_price_list != actual_price_list:
            to_delete = []

            for product_quote in quote.products.all():
                try:
                    plan = actual_price_list.items.get(model=product_quote.plan)
                    product = product_quote.product
                    if product.location:
                        country = product.location.country
                    else:
                        country = product.customer.country
                    country_category = get_country_category(country)
                    plan_price = getattr(plan, "cat{}_price".format(country_category))
                    if plan_price is None:
                        product_quote.plan = None
                        product_quote.price = Decimal(0)
                    else:
                        if product_quote.plan[2] == 'C':
                            # coterminus or 1 year
                            increase = product_quote.end_date - product_quote.start_date
                            daily_cost = Decimal(plan_price) / Decimal(365)
                            price = daily_cost * increase.days
                            product_quote.price = price.quantize(Decimal('.01'))
                        else:
                            # 3 or 5 year
                            product_quote.price = Decimal(plan_price)
                    product_quote.save()

                except ObjectDoesNotExist:
                    # Product quote marked for delete.
                    to_delete.append(product_quote.pk)

            quote.products.filter(pk__in=to_delete).delete()
        serializer = self.get_serializer(quote)
        return Response(serializer.data)

    @detail_route(methods=['get'])
    def download(self, request, pk=None):
        quote = self.get_object()
        xls = generate_report(quote)
        filename = "{}-{}-{}v{}.xls".format(
            quote.opportunity.customer.business_name,
            quote.name,
            quote.date_created,
            quote.version
        ).replace(' ', '_')

        # Create an HttpResponse and write the XLS file into it.
        response = HttpResponse(content_type="application/ms-excel")
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        xls.save(response)

        return response

    @detail_route(methods=['post'])
    def email(self, request, pk=None):
        """
        Action to send the user to the quote's customer with a link to the
        quote.
        """
        quote = self.get_object()
        customer = quote.opportunity.customer
        send_quote_email(customer, quote)

        return Response()


class ProductQuoteViewSet(DestroyModelMixin, GenericViewSet):
    """
    ViewSet to delete ProductQuotes manually.

    Overrides the `perform_delete` method so that the associated Quote is saved
    and thus its last_modified date updated.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = ProductQuoteSerializer

    def get_queryset(self):
        return ProductQuote.objects.filter(
            quote__opportunity__author=self.request.user
        )

    def perform_destroy(self, instance):
        instance.quote.save()
        super(ProductQuoteViewSet, self).perform_destroy(instance)


class GuestQuoteViewSet(RetrieveModelMixin, UpdateModelMixin, GenericViewSet):
    serializer_class = GuestQuoteSerializer
    lookup_field = 'tracking_number'
    queryset = Quote.objects.all()

    @detail_route(methods=['get'])
    def download(self, request, tracking_number=None):
        quote = self.get_object()
        xls = generate_report(quote)
        filename = "{}-{}-{}v{}.xls".format(
            quote.opportunity.customer.business_name,
            quote.name,
            quote.date_created.strftime("%Y-%m-%d"),
            quote.version
        ).replace(' ', '_')

        # Create an HttpResponse and write the XLS file into it.
        response = HttpResponse(content_type="application/ms-excel")
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        xls.save(response)

        return response

    @detail_route(methods=['post'])
    def feedback(self, request, tracking_number=None):
        """
        Action to leave feedback on a quote.
        """
        quote = self.get_object()

        serializer = QuoteFeedbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(quote=quote)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class PasswordResetView(APIView):
    """
    Generates and emails a token to reset a user's password.
    """
    permission_classes = (IsUnauthenticated,)
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
        return Response(status=status.HTTP_201_CREATED)

password_reset = PasswordResetView.as_view()


class PasswordResetConfirmView(APIView):
    """
    Generates and emails a token to reset a user's password.
    """
    permission_classes = (IsUnauthenticated,)
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request}
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()

password_reset_confirm = PasswordResetConfirmView.as_view()


class ContactFormView(APIView):
    """
    Contact form for the landing page.
    """
    serializer_class = ContactFormSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request}
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'success': True})

contact_form = ContactFormView.as_view()
