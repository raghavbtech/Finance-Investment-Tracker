"""
URL configuration for app1 project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from investment import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('bases.urls')),
    path("investment/",include('investment.urls')),
     path('admin_user/', views.admin_user_view, name='admin_user'),
    path('admin_user/profile/delete/<int:pk>/', views.delete_profile, name='delete_profile'),   
path('admin_user/investment/delete/<int:pk>/', views.delete_investment, name='delete_investment'),
path('admin_user/transaction/delete/<int:pk>/', views.delete_transaction, name='delete_transaction'),   
path('admin_user/user/delete/<int:pk>/', views.delete_user, name='delete_user'),

]
