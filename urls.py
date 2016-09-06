from django.conf.urls import patterns, include, url

from rest_framework.routers import DefaultRouter

from core.views import (
    login, logout, ContractViewSet, CustomerViewSet, ProductViewSet,
    LocationViewSet, OpportunityViewSet, ProductQuoteViewSet, PartnerViewSet,
    QuoteViewSet, UserViewSet, GuestQuoteViewSet, generate_quote,
    import_inventory, import_price_list, user_profile, single_price_list,
    multiple_price_list, add_products_to_quote, remove_products_from_quote,
    password_reset, password_reset_confirm, contact_form,
)


router = DefaultRouter()
router.register(r'contract', ContractViewSet, base_name='contract')
router.register(r'customer', CustomerViewSet, base_name='customer')
router.register(r'product', ProductViewSet, base_name='product')
router.register(r'location', LocationViewSet, base_name='location')
router.register(r'opportunity', OpportunityViewSet, base_name='opportunity')
router.register(r'product-quote', ProductQuoteViewSet, base_name='product-quote')  # NOQA
router.register(r'quote', QuoteViewSet, base_name='quote')
router.register(r'guest/quote', GuestQuoteViewSet, base_name='guest-quote')
router.register(r'partner', PartnerViewSet, base_name='partner')
router.register(r'user', UserViewSet, base_name='user')


urlpatterns = patterns(
    '',
    url(r'^login/$', login, name='login'),
    url(r'^logout/$', logout, name='logout'),
    url(r'^me/$', user_profile, name='user-profile'),
    url(r'^guest/password-reset/$', password_reset, name='password-reset'),
    url(r'^guest/password-reset-confirm/$', password_reset_confirm, name='password-reset-confirm'),  # NOQA
    url(r'^contact/$', contact_form, name='contact-form'),

    # Price list related views.
    url(r'^price-list/(?P<pk>\d+)/$', single_price_list, name='price-list-single'),  # NOQA
    url(r'^price-list/$', multiple_price_list, name='price-list-multiple'),

    url(r'^import/price-list/$', import_price_list, name='price-list-import'),
    url(r'^import/inventory/$', import_inventory, name='inventory-import'),

    url(r'^quote/generate/$', generate_quote, name='generate-quote'),
    url(r'^quote/add-products/$', add_products_to_quote, name='add-products-to-quote'),  # NOQA
    url(r'^quote/remove-products/$', remove_products_from_quote, name='remove-products-from-quote'),  # NOQA

    url(r'^', include(router.urls)),
)
