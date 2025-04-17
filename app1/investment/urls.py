from django.urls import path
from investment import views

urlpatterns = [

    path('logout/', views.logout_user, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('add/', views.add_investment, name='add_investment'),
    path('export/excel/', views.export_excel, name='export_excel'),
    path('export/pdf/', views.export_pdf, name='export_pdf'),
    path('update/<int:id>/', views.update_investment, name='update_investment'),
    path('delete/<int:id>/', views.delete_investment, name='delete_investment'),
    path('live-price/<str:symbol>/', views.live_price, name='live_price'),
    path('get-historical-price/', views.get_historical_price, name='get_historical_price'),
    path('get-index-prices/', views.get_index_prices, name='get_index_prices'),



]
