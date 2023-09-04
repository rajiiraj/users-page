import os  # Add this import at the beginning of your views.py
from django.conf import settings  # Add this import at the beginning of your views.py
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
from django.http import HttpResponse, Http404  # Import Http404
from django.db.models import Q
from django.http import HttpResponse 
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import make_password
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.utils import timezone
from .models import Documents
from django.views.decorators.csrf import csrf_exempt  # Import this decorator
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from urllib.parse import quote  # Import quote function for URL encoding
from django.core.files.storage import FileSystemStorage
from django.http import FileResponse, HttpResponseNotFound
from pathlib import Path
import shutil
from django.http import Http404, FileResponse
from django.http import JsonResponse  # Import JsonResponse






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


def user_report(request):
    total_users = User.objects.count()
    active_users = User.objects.filter(last_login__isnull=False).count()

    today = timezone.now().date()
    users_joined_today = User.objects.filter(date_joined__date=today).count()

    this_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    users_joined_this_month = User.objects.filter(date_joined__gte=this_month_start).count()

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'users_joined_today': users_joined_today,
        'users_joined_this_month': users_joined_this_month,
    }
    return render(request, 'user_report.html', context)


@csrf_exempt
def document_list(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('document')

        if uploaded_file:
            # Check if the uploaded file has an allowed file extension
            allowed_extensions = ['pdf', 'doc', 'txt']
            file_extension = uploaded_file.name.split('.')[-1].lower()

            if file_extension in allowed_extensions:
                # Specify the directory where you want to save the file
                upload_dir = os.path.join(settings.BASE_DIR, 'uploadfile')
                os.makedirs(upload_dir, exist_ok=True)  # Create the directory if it doesn't exist

                # Use the original filename of the uploaded file
                original_filename = uploaded_file.name

                # Construct the full path to save the file
                full_path = os.path.join(upload_dir, original_filename)

                # Save the uploaded file to the specified location
                with open(full_path, 'wb') as destination:
                    for chunk in uploaded_file.chunks():
                        destination.write(chunk)

                # Create a new document entry in the database
                document = Documents(
                    document_name=original_filename,
                    document_type=file_extension,
                    document_size=uploaded_file.size,
                    uploaded_date=timezone.now(),
                )
                document.save()
                
            else:
                # Display an error message if the file extension is not allowed
                error_message = 'Please upload only PDF, DOC, or text files.'
                documents = Documents.objects.all()
                context = {'documents': documents, 'error_message': error_message}
                return render(request, 'document_list.html', context)

        # After successfully processing the POST request, redirect to the same page (GET request)
        return redirect('document_list')

    documents = Documents.objects.all()
    context = {'documents': documents}
    return render(request, 'document_list.html', context)

@csrf_exempt
def serve_document(request, document_id):
    document = get_object_or_404(Documents, pk=document_id)

    file_directory = os.path.join(settings.BASE_DIR, 'uploadfile')

    file_path = os.path.join(file_directory, document.document_name)

    if os.path.isfile(file_path):
        response = FileResponse(open(file_path, 'rb'), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{document.document_name}"'
        return response
    else:
        raise Http404("File not found")





@csrf_exempt
@require_POST
def delete_document(request):
    document_id = request.POST.get('id')
    
    try:
        document = Documents.objects.get(pk=document_id)

        # Get the path to the file
        file_path = os.path.join(settings.BASE_DIR, 'uploadfile', document.document_name)

        if os.path.exists(file_path):
            # Delete the file from the folder
            os.remove(file_path)

        # Now, delete the database entry
        document.delete()

        return JsonResponse({'message': 'Document deleted successfully.'}, status=200)
    except Documents.DoesNotExist:
        return JsonResponse({'error': 'Document not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")