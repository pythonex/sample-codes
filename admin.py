from django.contrib import admin

from core.models import Partner, User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    fields = (
        'email', 'first_name', 'last_name', 'var', 'is_var_admin', 'is_admin',
        'is_active', 'last_login',
    )
    readonly_fields = ('last_login', )


@admin.register(Partner)
class PartnerAdmin(admin.ModelAdmin):
    pass
