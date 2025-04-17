from django.urls import path
from bases import views

urlpatterns = [
    path("",views.homepage_view, name='home'),
    path("about/", views.about_view, name='about'),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('contact/', views.contact_view , name='contactt'),
    path('tax/', views.tax_view, name="taxcalculator"),
   
    path('profile/', views.profile_view, name='profile'),
    path('transactions/', views.transaction_list, name='transaction_list'),
    


    path('create/', views.transaction_create, name='transaction_create'),
    path('update/<int:pk>/', views.transaction_update, name='transaction_update'),
    path('delete/<int:pk>/', views.transaction_delete, name='transaction_delete'),
    path('profile/update/', views.profile_update_view, name='profile_update'),
]


