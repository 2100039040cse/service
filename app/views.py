import socket
import uuid
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from .models import UserProfile
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
def index(request):
    return render(request, "app/index.html")

def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect("index")
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect("index")

        try:
            # Create user
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()

            # Generate verification token
            token = str(uuid.uuid4())
            profile = UserProfile.objects.create(user=user, verification_token=token)
            profile.save()

            # Send verification email
            verification_link = f"http://127.0.0.1:8000/verify/{token}/"
            send_mail(
                "Verify your email",
                f"Click the link to verify your email: {verification_link}",
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            messages.success(request, "Registration successful. Check your email to verify your account.")
            return redirect("login")

        except (socket.timeout, socket.gaierror, OSError):
            # Email failed to send, delete user
            user.delete()
            messages.error(request, "Email sending failed. Please use Mobile Data and try again.")
            return redirect("index")

    return render(request, "app/index.html")

def verify_email(request, token):
    try:
        profile = UserProfile.objects.get(verification_token=token)
        profile.is_verified = True
        profile.verification_token = None
        profile.save()
        messages.success(request, "Email verified successfully!")
        # return redirect("login")
        return redirect("index")
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid verification link.")
        # return redirect("login")
        return redirect("index")
    
def login_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Retrieve the user object to check if the account is active
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        # If the user exists but is inactive
        if user and not user.is_active:
            messages.error(request, "Your account is currently disabled by admin. Please contact the admin.")
            # return render(request, "app/login.html")
            return render(request, "app/index.html")

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Check if email is verified (for non-superuser and non-staff users)
            if not user.is_superuser and not user.is_staff:
                profile = UserProfile.objects.get(user=user)
                if not profile.is_verified:
                    messages.error(request, "Please verify your email before logging in.")
                    # return render(request, "app/login.html")
                    return render(request, "app/index.html")

            # Log in the user
            login(request, user)
            messages.success(request, "Login successful!")

            # Redirect based on user type
            if user.is_superuser:
                return redirect("admin_profile")  # Redirect to admin profile page
            elif user.is_staff:
                return redirect("staff_profile")  # Redirect to staff profile page
            else:
                return redirect("profile")  # Redirect to regular user profile page
        else:
            # Invalid credentials
            messages.error(request, "Invalid username or password.")

    # return render(request, "app/login.html")  
    return render(request, "app/index.html")
 



@login_required
def logout_user(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("index")


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
            token = str(uuid.uuid4())
            profile = UserProfile.objects.get(user=user)
            profile.reset_token = token
            profile.save()

            reset_link = f"http://127.0.0.1:8000/reset-password/{token}/"
            send_mail(
                "Reset Your Password",
                f"Click the link to reset your password: {reset_link}",
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            messages.success(request, "Password reset link sent to your email.")
            return redirect("login")
        except User.DoesNotExist:
            messages.error(request, "No account found with this email.")
            return redirect("forgot_password")
    return render(request, "app/forgot_password.html")


def reset_password(request, token):
    try:
        profile = UserProfile.objects.get(reset_token=token)
        if request.method == "POST":
            new_password = request.POST.get("password")
            confirm_password = request.POST.get("confirm_password")

            if new_password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return redirect(f"/reset-password/{token}/")

            user = profile.user
            user.set_password(new_password)
            user.save()
            profile.reset_token = None
            profile.save()

            messages.success(request, "Password reset successful! You can now log in.")
            return redirect("login")
        return render(request, "app/reset_password.html", {"token": token})
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid or expired password reset link.")
        return redirect("index")

@login_required
def profile(request):
    return render(request, "app/user/profile.html")



@login_required
def edit_profile(request):
    if request.method == "POST":
        if "change_password" in request.POST:
            current_password = request.POST.get("current_password")
            new_password = request.POST.get("new_password")
            confirm_password = request.POST.get("confirm_password")

            # Check current password
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect.")
            elif new_password != confirm_password:
                messages.error(request, "New passwords do not match.")
            else:
                # Update the password
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Keep the user logged in
                messages.success(request, "Password changed successfully!")
                return redirect("login")

        elif "delete_account" in request.POST:
            current_password = request.POST.get("current_password_delete")

            # Check if the current password is correct
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect. Account deletion failed.")
            else:
                # Delete the user's account
                user = request.user
                user.delete()
                messages.success(request, "Account deleted successfully.")
                return redirect("index")  # Redirect to the homepage

    return render(request, "app/user/edit_profile.html")















@login_required
def admin_profile(request):
    return render(request, "app/admin/admin_profile.html")

@login_required
def admin_edit_profile(request):
    if request.method == "POST":
        if "change_password" in request.POST:
            current_password = request.POST.get("current_password")
            new_password = request.POST.get("new_password")
            confirm_password = request.POST.get("confirm_password")

            # Check current password
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect.")
            elif new_password != confirm_password:
                messages.error(request, "New passwords do not match.")
            else:
                # Update the password
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Keep the user logged in
                messages.success(request, "Password changed successfully!")
                return redirect("login")

        elif "delete_account" in request.POST:
            current_password = request.POST.get("current_password_delete")

            # Check if the current password is correct
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect. Account deletion failed.")
            else:
                # Delete the user's account
                user = request.user
                user.delete()
                messages.success(request, "Account deleted successfully.")
                return redirect("index")  # Redirect to the homepage

    return render(request, "app/admin/admin_edit_profile.html")


@login_required
def toggle_user_status(request, user_id):
    if request.method == "POST":
        user = User.objects.get(id=user_id)
        user.is_active = not user.is_active
        user.save()
        messages.success(request, f"User {user.username} is now {'enabled' if user.is_active else 'disabled'}.")
    return redirect("users_list")



@login_required
def users_list(request):
    if request.user.is_superuser:  # Restrict access to superusers
        users = User.objects.all()  # Fetch all users
        return render(request, "app/admin/users_list.html", {"users": users})
    else:
        messages.error(request, "You are not authorized to view this page.")
        return redirect("admin_profile")












@login_required
def staff_profile(request):
    return render(request, "app/staff/staff_profile.html")


@login_required
def staff_edit_profile(request):
    if request.method == "POST":
        if "change_password" in request.POST:
            current_password = request.POST.get("current_password")
            new_password = request.POST.get("new_password")
            confirm_password = request.POST.get("confirm_password")

            # Check current password
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect.")
            elif new_password != confirm_password:
                messages.error(request, "New passwords do not match.")
            else:
                # Update the password
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Keep the user logged in
                messages.success(request, "Password changed successfully!")
                return redirect("login")

        elif "delete_account" in request.POST:
            current_password = request.POST.get("current_password_delete")

            # Check if the current password is correct
            if not request.user.check_password(current_password):
                messages.error(request, "Current password is incorrect. Account deletion failed.")
            else:
                # Delete the user's account
                user = request.user
                user.delete()
                messages.success(request, "Account deleted successfully.")
                return redirect("index")  # Redirect to the homepage

    return render(request, "app/staff/staff_edit_profile.html")
