from enum import member
from urllib import request
import csv
from django.db.models import Count, Sum
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, logout,update_session_auth_hash
from .forms import MaterialDetailForm, UserRegistrationForm, LoginForm,CustomPasswordResetForm ,UserProfileForm
from django.contrib.auth.views import LoginView
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from .models import MaterialDetail, MaterialRequest, MemberDetail, MaterialComment,User
from django.core.mail import send_mail
from django.urls import reverse_lazy
from django.contrib.messages.views import SuccessMessageMixin
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from .models import CLASS_CHOICES
from django.shortcuts import redirect, get_object_or_404
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.storage import FileSystemStorage
from django.core.exceptions import ValidationError
from django.db import transaction


def login(request):
    return render(request,'registration/login.html')
def forgot(request):
    return render(request,'registration/forgot.html')
def about(request):
    return render(request, 'headandfoot/about.html')
def contact(request):
    return render(request, 'headandfoot/contact.html')
def services(request):
    return render(request, 'headandfoot/services.html')
def layout(request):
    return render(request, 'headandfoot/layout.html')
def admin(request):
    return render(request, 'users/admin.html')
def material(request):
    materials = MaterialDetail.objects.all()  # Fetch all materials from the database
    return render(request, 'admin/material.html', {'materials': materials})

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST, current_user=request.user)
        if form.is_valid():
            try:
                # Begin transaction
                with transaction.atomic():
                    # Save the user first
                    user = form.save(commit=False)
                    user.role = form.cleaned_data['role']
                    user.set_password(form.cleaned_data['password1'])
                    user.save()

                    # Check if MemberDetail already exists
                    member, created = MemberDetail.objects.get_or_create(
                        user=user,
                        defaults={
                            'phone_number': form.cleaned_data.get('phone_number', ''),
                            'role': form.cleaned_data['role'],
                            'registered_at': user.date_joined
                        }
                    )
                    
                    # If MemberDetail exists, update it
                    if not created:
                        member.phone_number = form.cleaned_data.get('phone_number', '')
                        member.role = form.cleaned_data['role']
                        member.save()

                # Try to send email outside the transaction
                try:
                    subject = 'Welcome to Our Website!'
                    message = f'Hello {user.username},\n\nYour account has been successfully created.\n\n' \
                              f'Username: {user.username}\nPassword: {form.cleaned_data["password1"]}\n\n' \
                              f'Best regards,\nYour Website Team'
                    from_email = settings.EMAIL_HOST_USER
                    recipient_list = [user.email]
                    send_mail(subject, message, from_email, recipient_list)
                except Exception as e:
                    print(f"Email error: {e}")
                    messages.warning(request, "Account created but confirmation email could not be sent.")

                messages.success(request, 'Registration successful!')
                return redirect('teacher')

            except Exception as e:
                print(f"Registration error: {str(e)}")
                messages.error(request, f"An error occurred during registration: {str(e)}")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserRegistrationForm(current_user=request.user)

    return render(request, 'registration/register.html', {'form': form})
    
def update_materials_list(request):
    # Fetch all materials and their related comments
    materials = MaterialDetail.objects.prefetch_related('materialcomment_set').all().order_by('-updated_date')

    context = {
        'materials': materials,
    }
    return render(request, 'admin/update_materials_list.html', context)

# views.py
class CustomLoginView(LoginView):
    template_name = 'registration/login.html'
    authentication_form = LoginForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['role'] = self.request.GET.get('role')  # Get role from the query parameter
        return context

    def form_valid(self, form):
        user = form.get_user()
        requested_role = self.request.GET.get('role')  # Get role from URL parameter
        
        # Check if the user is a superuser
        if user.is_superuser:
            auth_login(self.request, user)
            return redirect('admin')  # Redirect superusers to the admin panel

        # Debug print statements
        print(f"User Role: {getattr(user, 'role', None)}")  # Assuming the User model has a `role` attribute
        print(f"Requested Role: {requested_role}")
        
        # Handle role-based redirection
        if getattr(user, 'role', None) == requested_role:
            auth_login(self.request, user)
            if user.role == 'teacher':
                return redirect('teacher_choices')  # Replace with your teacher dashboard URL
            elif user.role == 'student':
                return redirect('class_choices')  # Replace with your student dashboard URL
        else:
            messages.error(self.request, f"Access denied. This login is for {requested_role}s only.")
            return redirect(f"{reverse('login')}?role={requested_role}")

    def form_invalid(self, form):
        messages.error(self.request, "Invalid username or password.")
        return self.render_to_response(self.get_context_data(form=form))
        
def home(request):
    # If user is already logged in, redirect to appropriate dashboard
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect('admin')
        elif request.user.role == 'teacher':
            return redirect('teacher_choices')
        elif request.user.role == 'student':
            return redirect('class_choices')
    return render(request, 'home.html')

@login_required(login_url='login')
def teacher(request):
    if request.user.role != 'teacher':
        messages.error(request, 'Access denied. Teachers only.')
        return redirect('home')
    members = MemberDetail.objects.all().order_by('-registered_at')
    return render(request, 'users/teacher.html', {'members': members})

@login_required(login_url='login')
def student(request):
    if request.user.role != 'student':
        messages.error(request, 'Access denied. Students only.')
        return redirect('home')
    return render(request, 'users/class_choices.html')


@login_required(login_url='login')
def junior(request):
    if not request.user.is_authenticated:
        return redirect('login')
    materials = MaterialDetail.objects.all()
    return render(request, 'users/junior.html', {'materials': materials})

def logout_view(request):
    logout(request)
    request.session.flush()
    messages.success(request, 'You have been logged out successfully.')
    return redirect('home')



@login_required
def student(request, target_class):
    materials = MaterialDetail.objects.filter(target_class=target_class).order_by('-added_date')
    for material in materials:
        # Get all comments for each material
        material.comments = MaterialComment.objects.filter(material=material)

    return render(request, 'users/student.html', {'materials': materials})

def student_view(request, class_choice):
    materials = MaterialDetail.objects.filter(target_class=class_choice)  # Filter materials by class choice
    return render(request, 'student.html', {'materials': materials})

@login_required
def teacher_choices_view(request):
    return render(request, 'users/teacher_choices.html')

@login_required
def class_choices_view(request):
    return render(request, 'users/class_choices.html', {'class_choices': CLASS_CHOICES})

@login_required
def teacher_page_view(request):
    # Check if the logged-in user is a superuser (admin)
    if request.user.is_superuser:
        # If logged-in user is a superuser, show only teachers
        users = User.objects.filter(role='teacher').select_related('member_detail').order_by('-registered_at')
    else:
        # If logged-in user is not a superuser, check their role directly from User model
        if request.user.role == 'teacher':
            # If the user is a teacher, show only students
            users = User.objects.filter(role='student').select_related('member_detail').order_by('-registered_at')
        else:
            # For other roles, show no users
            users = User.objects.none()

    context = {
        'members': users  # Keep the same context variable name for template compatibility
    }
    return render(request, 'users/teacher.html', context)


@login_required
def add_material_view(request):
    if request.method == "POST":
        form = MaterialDetailForm(request.POST, request.FILES)
        if form.is_valid():
            material = form.save(commit=False)
            material.uploaded_by = request.user
            material.save()
            messages.success(request, "Material added successfully.")
            return redirect('material')  # Replace with your success URL
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = MaterialDetailForm()
    
    return render(request, 'materialaddition/addmaterial.html', {'form': form})




@login_required
def add_comment(request, material_id):
    # Get the MaterialDetail instance
    material = get_object_or_404(MaterialDetail, id=material_id)
    
    # Retrieve the target class from the material (update if needed)
    target_class = material.target_class  # Ensure your model has this attribute
    
    if request.method == 'POST':
        comment_text = request.POST.get('comment')
        if comment_text:
            # Add the comment
            MaterialComment.objects.create(
                material=material,
                user=request.user,
                comment=comment_text
            )
            messages.success(request, 'Your comment has been added!')
        else:
            messages.error(request, 'Comment cannot be empty.')
    
    # Redirect to the filtered page with the target class
    return redirect('student', target_class=target_class) # Redirect to material details page after submitting the comment

@login_required
def add_comment_admin(request, material_id):
    if request.method == 'POST':
        material = get_object_or_404(MaterialDetail, id=material_id)
        comment_text = request.POST.get('comment')
        MaterialComment.objects.create(
            material=material,
            user=request.user,
            comment=comment_text
        )
        return redirect('update_materials_list')


@login_required(login_url='login')
def remove_member(request, user_id):
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Get the user or return 404
                user = get_object_or_404(User, id=user_id)
                
                # Store username for message
                username = user.username
                
                # Delete the user (this will automatically delete the associated MemberDetail due to CASCADE)
                user.delete()
                
                messages.success(request, f'Member {username} has been successfully removed.')
        except Exception as e:
            messages.error(request, f'An error occurred while removing the member: {str(e)}')
    
    # Redirect back to the teacher page
    return redirect('teacher')  # Redirect to the member list page
    
@login_required
def send_request(request, material_id):
    material = get_object_or_404(MaterialDetail, id=material_id)
    teacher = material.uploaded_by

    target_class = material.target_class
    # Check if the student already sent a request for the same material
    existing_request = MaterialRequest.objects.filter(material=material, student=request.user).first()
    if existing_request:
        messages.error(request, "You have already requested this material.")
        return redirect('student', target_class=target_class)  # Replace with your materials page URL name

    # Create the request
    new_request = MaterialRequest.objects.create(material=material, student=request.user)
    print(f"New MaterialRequest created: {new_request.id}, Material: {material.name}, Teacher: {teacher.username}")

    messages.success(request, f"Request sent to {teacher.username}.")

    return redirect('student', target_class=target_class)


@login_required
def teacher_request(request, request_id=None):
    if not request.user.is_authenticated:
        messages.error(request, "You must be logged in to view requests.")
        return redirect('login')

    # Fetch requests
    if request_id:
        requests = MaterialRequest.objects.filter(
            material__uploaded_by=request.user, 
            id=request_id
        )
    else:
        requests = MaterialRequest.objects.filter(
            material__uploaded_by=request.user
        ).order_by('-requested_at')

    if not requests.exists():
        messages.info(request, "No requests found for materials you uploaded.")

    if request.method == 'POST':
        delivered_request_id = request.POST.get('mark_as_delivered')

        if delivered_request_id:
            try:
                material_request = get_object_or_404(MaterialRequest, id=delivered_request_id)
                
                # Use the model's deliver method
                if material_request.status == 'Approved':
                    material_request.deliver()
                    messages.success(request, f"The request for {material_request.material.name} has been marked as delivered.")
                else:
                    messages.error(request, "Only approved requests can be marked as delivered.")
                
                return redirect('requests')  # Redirect to the same page to refresh the list
            
            except ValueError as e:
                messages.error(request, str(e))
                return redirect('requests')

    return render(request, 'teacher/requests.html', {'requests': requests})



def custom_password_reset(request):
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                # Generate reset link
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_link = request.build_absolute_uri(
                    reverse('custom_password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
                )

                # Send email
                send_mail(
                    subject="Password Reset Request",
                    message=f"Click the link to reset your password: {reset_link}",
                    from_email="your-email@example.com",
                    recipient_list=[email],
                    fail_silently=False,
                )

                messages.success(request, "A reset link has been sent to your email.")
                return redirect('custom_password_reset')
            except User.DoesNotExist:
                messages.error(request, "No account found with this email address.")
    else:
        form = CustomPasswordResetForm()

    return render(request, 'password_reset/custom_password_reset.html', {'form': form})
def custom_password_reset_confirm(request, uidb64, token):
    try:
        # Decode the user's ID
        user_id = force_bytes(urlsafe_base64_decode(uidb64)).decode()
        user = User.objects.get(pk=user_id)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                # Use set_password to hash and save the password
                user.set_password(new_password)
                user.save()

                messages.success(request, "Password reset successfully.")
                return redirect('login')
            else:
                messages.error(request, "Passwords do not match.")
        return render(request, 'password_reset/custom_password_reset_confirm.html')
    else:
        messages.error(request, "Invalid or expired token.")
        return redirect('custom_password_reset')
@login_required
def approve_request(request, request_id):
    material_request = get_object_or_404(MaterialRequest, id=request_id)
    
    # Update the status of the request to 'approved'
    material_request.status = 'approved'
    material_request.save()

    messages.success(request, f"The request for {material_request.material.name} has been approved.")
    return redirect('requests')

@login_required
def reject_request(request, request_id):
    material_request = get_object_or_404(MaterialRequest, id=request_id)
    
    # Update the status of the request to 'rejected'
    material_request.status = 'rejected'
    material_request.save()

    messages.success(request, f"The request for {material_request.material.name} has been rejected.")
    return redirect('requests')

def my_requests(request):
    # Fetch the material requests for the logged-in user
    requests = MaterialRequest.objects.filter(student=request.user).order_by('-requested_at')
    return render(request, 'student/my_requests.html', {'requests': requests})

def approve_request(request, request_id):
    material_request = get_object_or_404(MaterialRequest, id=request_id)

    # Update the request status to "Approved"
    material_request.status = 'Approved'
    material_request.save()

    messages.success(request, f"Request for {material_request.material.name} has been approved.")
    return redirect('requests')  # or redirect back to your page

def reject_request(request, request_id):
    material_request = get_object_or_404(MaterialRequest, id=request_id)

    # Update the request status to "Rejected"
    material_request.status = 'Rejected'
    material_request.save()

    messages.success(request, f"Request for {material_request.material.name} has been rejected.")
    return redirect('requests')  # or redirect back to your page


@login_required
def profile_view(request):
    # Ensure the user has a MemberDetail instance
    try:
        member_detail = request.user.member_detail
    except ObjectDoesNotExist:
        # Create a MemberDetail instance for the user if it doesn't exist
        member_detail = MemberDetail.objects.create(user=request.user)

    # Initialize the forms
    profile_form = UserProfileForm(instance=member_detail, user_instance=request.user)
    password_form = PasswordChangeForm(request.user)

    if request.method == 'POST':
        # Handle profile update
        if 'update_profile' in request.POST:
            profile_form = UserProfileForm(request.POST, instance=member_detail, user_instance=request.user)
            if profile_form.is_valid():
                profile_form.save()
                return redirect('profile')  # Redirect to the profile page after saving

        # Handle password change
        elif 'change_password' in request.POST:
            password_form = PasswordChangeForm(request.user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)  # Keep the user logged in after password change
                return redirect('profile')

    # Render the profile page
    context = {
        'profile_form': profile_form,
        'password_form': password_form,
        'member_detail': member_detail,  # Pass the MemberDetail instance to the template
    }
    return render(request, 'headandfoot/profile.html', context)


def update_material(request, material_id):
    material = get_object_or_404(MaterialDetail, id=material_id)
    
    # Define the list of target class choices
    target_class_choices = ["Grade 6","Grade 7", "Grade 8", "B.Sc Physics", "B.Sc Chemistry",]
    
    if request.method == 'POST':
        # Update material fields from POST data
        material.name = request.POST.get('name')
        material.description = request.POST.get('description')
        material.category = request.POST.get('category')
        material.quantity_available = request.POST.get('quantity_available')
        material.price = request.POST['price']
        material.target_class = request.POST.get('target_class')

        # Check if a new file is uploaded
        if 'file' in request.FILES:
            material.file = request.FILES['file']

        try:
            # Validate and save the material
            material.clean()
            material.save()
            messages.success(request, 'Material updated successfully.')
            return redirect('update_materials_list')
        except ValidationError as e:
            messages.error(request, f"Error: {e.message}")

    return render(request, 'admin/update_material.html', {
        'material': material,
        'target_class_choices': target_class_choices
    })


def remove_material(request, material_id):
    material = get_object_or_404(MaterialDetail, id=material_id)

    if request.method == 'POST':
        material.delete()
        messages.success(request, 'Material removed successfully.')
        return redirect('update_materials_list')

    return render(request, 'admin/confirm_remove.html', {'material': material})

def generate_reports(request):
    """
    Generates reports on material usage and distribution efficiency.
    """
    # Total materials
    total_materials = MaterialDetail.objects.count()

    # Total requests
    total_requests = MaterialRequest.objects.count()

    # Approved requests
    approved_requests = MaterialRequest.objects.filter(status='Approved').count()

    # Most requested materials
    most_requested_materials = (
        MaterialRequest.objects.values('material__name')
        .annotate(request_count=Count('id'))
        .order_by('-request_count')[:5]
    )

    # Requests grouped by target class
    requests_by_class = (
        MaterialRequest.objects.values('material__target_class')
        .annotate(total_requests=Count('id'))
        .order_by('-total_requests')
    )

    # Distribution efficiency: (approved requests / total materials)
    distribution_efficiency = (
        approved_requests / total_materials * 100 if total_materials > 0 else 0
    )

    context = {
        'total_materials': total_materials,
        'total_requests': total_requests,
        'approved_requests': approved_requests,
        'most_requested_materials': most_requested_materials,
        'requests_by_class': requests_by_class,
        'distribution_efficiency': distribution_efficiency,
    }

    return render(request, 'admin/reports.html', context)

def buy_material(request, material_id):
    material = get_object_or_404(MaterialDetail, id=material_id)
    
    upi_id = "your_upi_id@bank"
    amount = material.price
    note = f"Payment for {material.name}"
    
    upi_qr_link = f"upi://pay?pa={upi_id}&pn=YourName&am={amount}&tn={note}"
    
    context = {
        'material': material,
        'upi_qr_link': upi_qr_link
    }
    return render(request, 'payment/buy_material.html', context)