from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User  # ✅ Add this
import yfinance as yf
from decimal import Decimal


class NSEStock(models.Model):
    symbol = models.CharField(max_length=20, unique=True)
    company_name = models.CharField(max_length=255)
    one_time_price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.symbol} - {self.company_name}"


class Investment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # ✅ Updated
    investment_id = models.AutoField(primary_key=True)
    investment_name = models.CharField(max_length=60)
    investment_date = models.DateField(default=timezone.localdate)
    investment_quantity = models.PositiveIntegerField()
    stock = models.ForeignKey(NSEStock, on_delete=models.CASCADE)
    buy_price = models.DecimalField(max_digits=10, decimal_places=2)

    def get_live_price(self):
        try:
            ticker = yf.Ticker(f"{self.stock.symbol}.NS")
            price = ticker.fast_info['last_price']
            print(f"Live price for {self.stock.symbol}: {price}")
            return float(price)
        except:
            return None

    def profit_loss(self):
        current_price = self.get_live_price()
        if current_price:
            current_price_decimal = Decimal(str(current_price))
            return round((current_price_decimal - self.buy_price) * self.investment_quantity, 2)
        return None

    def current_price_display(self):
        price = self.get_live_price()
        if price:
            return round(Decimal(str(price)), 2)
        return None

    def invested_value(self):
        return round(self.buy_price * self.investment_quantity, 2)

    def current_value(self):
        current_price = self.get_live_price()
        if current_price is not None:
            current_price_decimal = Decimal(str(current_price))
            return round(current_price_decimal * self.investment_quantity, 2)
        return None
