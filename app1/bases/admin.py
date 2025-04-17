from django.contrib import admin
from .models import Profile, Transaction

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio')
    search_fields = ('user__username', 'bio')


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('user', 'category', 'amount', 'description')
    search_fields = ('user__username', 'category', 'description')
    list_filter = ('category',)


