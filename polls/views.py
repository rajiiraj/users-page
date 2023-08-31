from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login  
from django.contrib.auth.models import User
from django.contrib import messages
from django.urls import reverse
from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.contrib.auth import logout
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.db.models import Q
from django.http import HttpResponse 
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import make_password
from django.views.decorators.http import require_POST
from django.urls import reverse





def user_login(request):
    if request.user.is_authenticated:
        return redirect('users')  # Redirect to the 'users' page if already authenticated

    if request.method == "POST":
        username_or_email = request.POST.get('username')
        password = request.POST.get('password')

        # Try to authenticate with either username or email
        user = authenticate(
            request, username=username_or_email, password=password
        )

        # If not successful, try again with email as username
        if user is None:
            try:
                user = User.objects.get(email=username_or_email)
                user = authenticate(
                    request, username=user.username, password=password
                )
            except User.DoesNotExist:
                user = None

        if user is not None:
            # Authentication succeeded, log the user in
            auth_login(request, user)
            return redirect('users')  # Assuming 'users' is the name of the URL pattern for the 'users.html' page
 # Redirect to the desired page after login
        else:
            # Authentication failed
            return render(request, 'login.html', {'error_message': 'Invalid credentials'})

    else:
        #print("singin.......")
        #print(request.__dict__)
        return render(request, 'login.html')


def signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        accept_terms = request.POST.get('accept_terms')  # Check if the terms are accepted

        if accept_terms:
            try:
                # Create a new user
                user = User.objects.create_user(username=username, password=password, email=email)
                user.first_name = firstname
                user.last_name = lastname
                user.save()

                # Log the user in
                auth_login(request, user)

                # Redirect to the 'showdata' page after successful signup
                return redirect('users')  # Assuming 'users' is the name of the URL pattern for the 'users.html' page

            except IntegrityError as e:
                if 'UNIQUE constraint' in str(e):
                    error_message = "An error occurred during signup. Please try again."

                else:
                    error_message = "Username or email already exists. Please try another."

                return render(request, 'signup.html', {'error_message': error_message})

    return render(request, 'signup.html')

@login_required
def user_edit(request):
    if request.method == "POST":
        user_id = request.POST.get("id")
        username = request.POST.get("username")
        email = request.POST.get("email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")

        try:
            user = User.objects.get(pk=user_id)
            is_logged_in_user = user == request.user  # Check if the edited user is the logged-in user

            user.username = username
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.save()

            if is_logged_in_user:
                messages.info(request, "Your account information has been updated. Please log in again.")
                logout(request)  # Log out the user

                # Redirect to the login page with the message
                return redirect('user_login')

            return JsonResponse({"message": "User updated successfully"})
        except User.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)

    return JsonResponse({"message": "Invalid request"}, status=400)





@login_required
def users_page(request):
    users = User.objects.all().order_by('id')
    change_password_url = reverse('change_password')  # Use 'change_password' as the argument
    return render(request, 'users.html', {'users': users, 'logged_in_user': request.user, 'change_password_url': change_password_url})



def redirect_to_login(request):
    return redirect('user_login') 

@login_required
def user_logout(request):
    logout(request)
    return redirect('user_login')

User = get_user_model()

@login_required
def delete_user(request, user_id):
    if request.method == "POST":
        try:
            user = User.objects.get(pk=user_id)
            # Check if the user being deleted is the logged-in user
            if user == request.user:
                logout(request)  # Log out the user
                user.delete()     # Delete the user
                return redirect('user_login')  # Redirect to the login page
            else:
                user.delete()  # Delete the user from both tables
                return redirect('users')  # Redirect to the users page

        except User.DoesNotExist:
            pass  # Handle the case where the user doesn't exist



@login_required
def user_search(request):
    search_query = request.GET.get('search', '')
    users = User.objects.filter(
        Q(username__icontains=search_query) |
        Q(email__icontains=search_query) |
        Q(id__icontains=search_query) |
        Q(first_name__icontains=search_query) |
        Q(last_name__icontains=search_query)
    )
    context = {'users': users, 'search_query': search_query}
    return render(request, 'users.html', context)



@login_required  # Ensure the user is logged in to access this view
@require_POST    # Only allow POST requests
def change_password_view(request):
    user_id = request.POST.get('id')
    new_password = request.POST.get('new_password')

    try:
        user = User.objects.get(id=user_id)
        user.set_password(new_password)
        user.save()
        return JsonResponse({'message': 'Password changed successfully.'}, status=200)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)




def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")