"""
URL configuration for workshop project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
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
from django.urls import include, path
from polls.views import user_login, redirect_to_login   # Import the renamed function
from polls.views import signup  # Import the renamed function


urlpatterns = [
    path("", redirect_to_login, name="redirect_to_login"),  # Redirect root URL to login page

    path("polls/", include("polls.urls")),
    path("admin/", admin.site.urls),
    path("login/", user_login, name="user_login"),
    path("signup/", signup)  # Use the renamed function

]