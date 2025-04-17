# utils.py

from nsetools import Nse
import yfinance as yf
from .models import NSEStock

def load_nse_stocks():
    nse = Nse()
    stock_list = nse.get_stock_codes()

    for symbol in stock_list:
        if symbol == 'SYMBOL' or '-' in symbol:
            continue  # skip invalid or special NSE symbols

        try:
            stock = yf.Ticker(f"{symbol}.NS")
            hist = stock.history(period="5d")

            if hist is None or hist.empty:
                print(f"⚠️ No data for {symbol}")
                continue

            price = float(hist['Close'].iloc[-1])

            NSEStock.objects.get_or_create(
                symbol=symbol,
                company_name=symbol,
                defaults={'one_time_price': round(price, 2)}
            )
            print(f"✅ Loaded {symbol}")
        except Exception as e:
            print(f"❌ Error with {symbol}: {e}")
