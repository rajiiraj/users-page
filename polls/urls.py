from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.user_login, name="user_login"),
    path("signup/", views.signup, name="signup"),
    path("users/", views.users_page, name="users"),
    path("", views.redirect_to_login, name="login_redirect"),
    path("logout/", views.user_logout, name="user_logout"),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('user_edit/', views.user_edit, name='user_edit'),
    path('user_search/', views.user_search, name='user_search'),
    path('change_password/', views.change_password_view, name='change_password'),
    path('user_report/', views.user_report, name='user_report'),
    path('documents/', views.document_list, name='document_list'),
    path('documents/serve/<int:document_id>/', views.serve_document, name='serve_document'),
    path('delete_document/', views.delete_document, name='delete_document'),

    

]
