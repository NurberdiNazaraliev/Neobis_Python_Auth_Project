from django.urls import path
from . import views


urlpatterns = [
    path('', views.homepage, name=''),
    path('signup', views.signup, name='signup'),
    path('login', views.login, name='login'),
    path('dashboard', views.dashboard, name='dashboard'),
    path('logout', views.user_logout, name='user_logout'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate')
]