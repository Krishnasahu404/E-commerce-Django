from  django.urls import path
from . import views

urlpatterns = [
    path("register/",views.register,name='register'),
    path("login/",views.login,name='login'),
    path("logout/",views.logout,name='logout'),
    
    path("activate/<uid64>/<token>/", views.activate, name='activate'),
    path("dashboard/", views.dashboard, name='dashboard'),
    path("", views.dashboard, name='dashboard'),
    
    path("forgotPassword/", views.forgotPassword, name='forgotPassword'),
    path("resetpassword_validate/<uid64>/<token>/", views.resetpassword_validate, name='resetpassword_validate'),
    path("resetpassword/", views.resetpassword, name='resetpassword'),
    
    
    
    
    
    
    
    
]
