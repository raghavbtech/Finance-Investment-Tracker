from investment.utils import load_nse_stocks
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login,logout
from django.shortcuts import render, redirect, get_object_or_404
from investment.models import Investment, NSEStock
from django.contrib.auth.models import User
from decimal import Decimal
import json
import openpyxl
from django.http import HttpResponse, JsonResponse
import yfinance as yf
from openpyxl.styles import Font
from django.template.loader import get_template
from xhtml2pdf import pisa
from io import BytesIO
from datetime import date, datetime, timedelta
from django.utils.dateparse import parse_date
from collections import defaultdict
from django.db.models import Sum
from nsetools import Nse





@login_required
def add_investment(request):
    user = request.user

    if request.method == "POST":
        symbol = request.POST.get('stock_symbol').upper()
        quantity = int(request.POST.get('quantity'))
        investment_name = request.POST.get('investment_name')
        investment_date = request.POST.get('investment_date')
        buy_price = Decimal(request.POST.get('buy_price'))

        try:
            stock = NSEStock.objects.get(symbol=symbol)
            Investment.objects.create(
                user=user,
                investment_name=investment_name or stock.company_name,
                investment_date=investment_date,
                investment_quantity=quantity,
                stock=stock,
                buy_price=buy_price
            )
            return redirect('dashboard')
        except NSEStock.DoesNotExist:
            return render(request, 'add_investment.html', {
                'error': f"Stock Symbol '{symbol}' not found",
                'stocks': NSEStock.objects.all()
            })

    return render(request, 'add_investment.html', {
        'stocks': NSEStock.objects.all()
    })


@login_required
def dashboard(request):
    user = request.user

    try:
        user = User.objects.get(username=user.username)
    except User.DoesNotExist:
        return redirect('login')

    investments = Investment.objects.filter(user=user)

    stock_filter = request.GET.get("stock")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    pl_filter = request.GET.get("pl")

    if stock_filter:
        investments = investments.filter(stock__symbol__icontains=stock_filter)

    if start_date:
        try:
            investments = investments.filter(investment_date__gte=start_date)
        except:
            pass

    if end_date:
        try:
            investments = investments.filter(investment_date__lte=end_date)
        except:
            pass

    if pl_filter == "profit":
        investments = [i for i in investments if (i.profit_loss() or 0) > 0]
    elif pl_filter == "loss":
        investments = [i for i in investments if (i.profit_loss() or 0) < 0]

    total_invested = Decimal('0.00')
    total_current = Decimal('0.00')
    stock_distribution = {}

    for inv in investments:
        total_invested += inv.invested_value()
        cv = inv.current_value()
        if cv:
            total_current += cv
        symbol = inv.stock.symbol
        stock_distribution[symbol] = stock_distribution.get(symbol, 0) + inv.invested_value()

    total_profit_loss = total_current - total_invested

    labels = list(stock_distribution.keys())
    data = [float(value) for value in stock_distribution.values()]

    chart_labels = json.dumps(labels)
    chart_data = json.dumps(data)

    top_gainer = None
    top_loser = None
    long_holders = []
    total_value = 0
    suggestion_distribution = {}

    for inv in investments:
        profit = inv.profit_loss() or 0
        current_value = inv.current_value() or 0
        invested = inv.invested_value()
        total_value += current_value
        suggestion_distribution[inv.stock.symbol] = suggestion_distribution.get(inv.stock.symbol, 0) + invested

        if not top_gainer or profit > top_gainer['profit']:
            top_gainer = {
                'name': inv.stock.symbol,
                'profit': profit,
                'percentage': (profit / invested) * 100 if invested > 0 else 0
            }

        if not top_loser or profit < top_loser['profit']:
            top_loser = {
                'name': inv.stock.symbol,
                'profit': profit,
                'percentage': (profit / invested) * 100 if invested > 0 else 0
            }

        if (date.today() - inv.investment_date).days >= 365:
            long_holders.append(inv.stock.symbol)

    high_concentration = None
    for symbol, val in suggestion_distribution.items():
        if (val / total_value) > 0.5:
            high_concentration = symbol
            break

    suggestions = []
    if top_gainer and top_gainer['profit'] > 0:
        suggestions.append(f"Your top gainer is {top_gainer['name']} (+₹{top_gainer['profit']:.2f}, {top_gainer['percentage']:.1f}%)")

    if top_loser and top_loser['profit'] < 0:
        suggestions.append(f"You might want to review {top_loser['name']} (₹{top_loser['profit']:.2f}, {top_loser['percentage']:.1f}%)")

    if long_holders:
        suggestions.append(f"You’ve held these for over a year: {', '.join(long_holders)}")

    if high_concentration:
        suggestions.append(f"⚠️ {high_concentration} is over 50% of your portfolio. Consider diversifying.")

    top_3 = sorted(investments, key=lambda i: i.profit_loss() or 0, reverse=True)[:3]

    total_pl = sum([inv.profit_loss() or 0 for inv in investments])

    monthly_summary = defaultdict(lambda: {'invested': 0, 'current': 0, 'pl': 0})

    for inv in investments:
        month_key = inv.investment_date.strftime('%b %Y')
        monthly_summary[month_key]['invested'] += float(inv.invested_value())
        monthly_summary[month_key]['current'] += float(inv.current_value() or 0)
        monthly_summary[month_key]['pl'] += float(inv.profit_loss() or 0)

    nse = Nse()
    try:
        nifty_50 = nse.get_index_quote('nifty 50')['lastPrice']
        sensex = nse.get_index_quote('sensex')['lastPrice']
        bank_nifty = nse.get_index_quote('nifty bank')['lastPrice']
        bankex = nse.get_index_quote('bankex')['lastPrice']
    except:
        nifty_50 = sensex = bank_nifty = bankex = "Unavailable"

    context = {
        'investments': investments,
        'total_invested': total_invested,
        'total_current': total_current,
        'total_profit_loss': total_profit_loss,
        'stock_distribution': stock_distribution,
        'chart_labels': chart_labels,
        'chart_data': chart_data,
        'suggestions': suggestions,
        'top_performers': top_3,
        'live_pl': total_pl,
        'monthly_summary': dict(monthly_summary),
        'nifty_50': nifty_50,
        'sensex': sensex,
        'bank_nifty': bank_nifty,
        'bankex': bankex
    }

    return render(request, 'dashboard1.html', context)


def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            request.session['username'] = user.username
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {
                'error': 'Invalid username or password'
            })

    return render(request, 'login.html')


@login_required
def export_excel(request):
    user = request.user
    investments = Investment.objects.filter(user=user)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Investment Summary"

    headers = ['ID', 'Name', 'Stock', 'Buy Price', 'Current Price', 'Quantity', 'Date', 'Invested Value', 'Current Value', 'Profit / Loss']
    ws.append(headers)

    for col in range(1, len(headers)+1):
        ws.cell(row=1, column=col).font = Font(bold=True)

    for inv in investments:
        row = [
            inv.investment_id,
            inv.investment_name,
            inv.stock.symbol,
            float(inv.buy_price),
            float(inv.current_price_display() or 0),
            inv.investment_quantity,
            inv.investment_date.strftime("%Y-%m-%d"),
            float(inv.invested_value()),
            float(inv.current_value() or 0),
            float(inv.profit_loss() or 0)
        ]
        ws.append(row)

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = 'attachment; filename=investment_summary.xlsx'
    wb.save(response)
    return response


@login_required
def export_pdf(request):
    user = request.user
    investments = Investment.objects.filter(user=user)

    template = get_template("pdf_template.html")
    context = {
        "user": user,
        "investments": investments,
    }
    html = template.render(context)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename=investment_summary.pdf'
    pisa_status = pisa.CreatePDF(html, dest=response)

    if pisa_status.err:
        return HttpResponse('PDF generation failed!')
    return response


@login_required
def update_investment(request, id):
    investment = get_object_or_404(Investment, pk=id)

    if request.method == 'POST':
        investment.investment_name = request.POST.get('investment_name')
        investment.stock = NSEStock.objects.get(symbol=request.POST.get('stock_symbol'))
        investment.investment_quantity = int(request.POST.get('quantity'))
        investment.buy_price = float(request.POST.get('buy_price'))
        date_str = request.POST.get('investment_date')
        if date_str:
            investment.investment_date = parse_date(date_str)
        investment.save()
        return redirect('dashboard')

    stocks = NSEStock.objects.all()
    return render(request, 'update_investment.html', {
        'investment': investment,
        'stocks': stocks,
    })


@login_required
def delete_investment(request, id):
    investment = get_object_or_404(Investment, pk=id)
    investment.delete()
    return redirect('dashboard')


@login_required
def live_price(request, symbol):
    try:
        ticker = yf.Ticker(f"{symbol}.NS")
        price = ticker.fast_info['last_price']
        return JsonResponse({'price': price})
    except:
        return JsonResponse({'error': 'Could not fetch'}, status=400)


@login_required
def get_historical_price(request):
    symbol = request.GET.get('symbol')
    date_str = request.GET.get('date')

    try:
        if not symbol or not date_str:
            return JsonResponse({'price': None})

        start_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        end_date = start_date + timedelta(days=1)

        ticker = yf.Ticker(f"{symbol}.NS")
        df = ticker.history(start=start_date, end=end_date)

        if df.empty:
            return JsonResponse({'price': None})

        price = df['Close'].iloc[0]
        return JsonResponse({'price': round(float(price), 2)})

    except Exception as e:
        print(f"Error fetching price for {symbol} on {date_str}: {e}")
        return JsonResponse({'price': None})


@login_required
def get_index_prices(request):
    def fetch(symbol):
        try:
            ticker = yf.Ticker(symbol)
            price = ticker.fast_info.get("last_price")
            if not price:
                # fallback to previous close
                price = ticker.history(period="1d")["Close"].iloc[-1]
            return round(price, 2)
        except Exception as e:
            print(f"Error fetching {symbol}: {e}")
            return "Unavailable"

    prices = {
        "nifty_50": fetch("^NSEI"),
        "sensex": fetch("^BSESN"),
        "bank_nifty": fetch("^NSEBANK"),
        "bankex": fetch("BSE-BANK.BO")
    }

    return JsonResponse(prices)



def logout_user(request):
    logout(request)
    return redirect('login')

from django.shortcuts import render
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from .models import  Investment
from bases.models import Profile,Transaction


def is_admin(user):
    return user.is_superuser

@user_passes_test(is_admin)
def admin_user_view(request):
    users = User.objects.all()
    profiles = Profile.objects.select_related('user')
    investments = Investment.objects.select_related('user', 'stock')
    transactions = Transaction.objects.select_related('user')

    context = {
        'users': users,
        'profiles': profiles,
        'investments': investments,
        'transactions': transactions,
    }
    return render(request, 'admin_user.html', context)



@user_passes_test(is_admin)
def delete_profile(request, pk):
    profile = get_object_or_404(Profile, pk=pk)
    profile.delete()
    return redirect('admin_user')

@user_passes_test(is_admin)
def delete_investment(request, pk):
    investment = get_object_or_404(Investment, pk=pk)
    investment.delete()
    return redirect('admin_user')

@user_passes_test(is_admin)
def delete_transaction(request, pk):
    transaction = get_object_or_404(Transaction, pk=pk)
    transaction.delete()
    return redirect('admin_user')

@user_passes_test(is_admin)
def delete_user(request, pk):
    user = get_object_or_404(User, pk=pk)
    user.delete()
    return redirect('admin_user')
