from django.contrib import admin
from .models import NSEStock, Investment

@admin.register(NSEStock)
class NSEStockAdmin(admin.ModelAdmin):
    list_display = ('symbol', 'company_name', 'one_time_price')
    search_fields = ('symbol', 'company_name')
    ordering = ('symbol',)


@admin.register(Investment)
class InvestmentAdmin(admin.ModelAdmin):
    list_display = (
        'investment_id',
        'user',
        'investment_name',
        'stock',
        'investment_quantity',
        'buy_price',
        'current_price_display',
        'investment_date',
        'profit_or_loss',
    )
    list_filter = ('investment_date', 'stock')
    search_fields = ('investment_name', 'stock__symbol', 'user__username')

    def profit_or_loss(self, obj):
        return obj.profit_loss()
    profit_or_loss.short_description = 'Profit / Loss'
