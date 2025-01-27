import re
from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm,SetPasswordForm
from django.contrib.auth import get_user_model
from django.contrib.auth import login
from .models import MemberDetail,User
from .models import MaterialDetail
from django.core.validators import MinValueValidator
from django.core.validators import RegexValidator


CLASS_CHOICES = [
    ("", "Select a class"),
    ("Grade 6", "Grade 6"),
    ("Grade 7", "Grade 7"),
    ("Grade 8", "Grade 8"),
    ("Grade 9", "Grade 9"),
    ("Grade 10", "Grade 10"),
    ("B.Sc Physics", "B.Sc Physics"),
    ("B.Sc Chemistry", "B.Sc Chemistry"),
]



ROLE_CHOICES = [
    ('student', 'Student'),
    ('teacher', 'Teacher'),
]

class LoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}),
        label='Username',
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}),
        label='Password',
    )


class UserRegistrationForm(UserCreationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}),
        label='Username',
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}),
        label='Email',
    )
    phone_number = forms.CharField(
    widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Phone Number',
        'required': True,
        'pattern': '\d{10}',
        'title': 'Phone number must be exactly 10 digits'
    }),
    label='Phone Number',
    validators=[RegexValidator(r'^\d{10}$', 'Phone number must be exactly 10 digits.')],
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}),
        label='Password',
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'}),
        label='Confirm Password',
    )
    role = forms.ChoiceField(
    choices=ROLE_CHOICES,  # Make sure this is imported from your models
    widget=forms.Select(attrs={'class': 'form-control'}),
    label='Role',
    )

    class Meta:
        model = get_user_model()  # Use the custom user model
        fields = ['username', 'email', 'phone_number', 'password1', 'password2', 'role']

    def __init__(self, *args, **kwargs):
        current_user = kwargs.pop('current_user', None)
        super().__init__(*args, **kwargs)

        if current_user:
            if current_user.is_superuser:
                self.fields['role'].initial = 'teacher'
            elif hasattr(current_user, 'member_detail') and current_user.member_detail.role == 'teacher':
                self.fields['role'].initial = 'student'
            else:
                self.fields['role'].initial = 'student'  # Default to student if no conditions met
                
        # Make role read-only
        self.fields['role'].widget = forms.HiddenInput()

    def clean_role(self):
        """
        Enforce the role to remain consistent with the logged-in user.
        """
        return self.fields['role'].initial  # Always return the initial value regardless of what was submitted
    
    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if not phone_number:
            raise forms.ValidationError("Phone number is required.")
        if not re.match(r'^\d{10}$', phone_number):
            raise forms.ValidationError("Phone number must be exactly 10 digits.")
        return phone_number
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match!")
        return cleaned_data


class CustomPasswordResetForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'}),
        max_length=254
    )

class MaterialDetailForm(forms.ModelForm):
    class Meta:
        model = MaterialDetail
        fields = ['name', 'description', 'category', 'quantity_available', 'target_class', 'price', 'file']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control'}),
            'category': forms.TextInput(attrs={'class': 'form-control'}),
            'quantity_available': forms.NumberInput(attrs={'class': 'form-control'}),
            'target_class': forms.Select(choices=CLASS_CHOICES, attrs={'class': 'form-control'}),
            'price': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'file': forms.ClearableFileInput(attrs={'class': 'form-control', 'required': 'required'}),
        }

    # Adding constraints with custom error messages
    price = forms.DecimalField(
        validators=[MinValueValidator(0, message="Price must be greater than or equal to 0.")],
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'})
    )
    
    quantity_available = forms.IntegerField(
        validators=[MinValueValidator(0, message="Quantity available must be greater than 0.")],
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )

    def clean(self):
        cleaned_data = super().clean()
        price = cleaned_data.get("price")
        quantity_available = cleaned_data.get("quantity_available")

        # Example of additional custom error handling
        if price is not None and price < -1:
            self.add_error('price', "Price cannot be negative.")
        
        if quantity_available is not None and quantity_available < 1:
            self.add_error('quantity_available', "Quantity cannot be negative or zero.")
        
        return cleaned_data

class UserProfileForm(forms.ModelForm):
    user = forms.CharField(
        label="Username",
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        required=True
    )

    class Meta:
        model = MemberDetail
        fields = ['phone_number']

    def __init__(self, *args, **kwargs):
        user_instance = kwargs.pop('user_instance', None)  # Pass the logged-in user instance
        super().__init__(*args, **kwargs)

        self.user_instance = user_instance  # Store the logged-in user instance
        if user_instance:
            self.fields['user'].initial = user_instance.username  # Set the initial username
            self.fields['email'].initial = user_instance.email  # Set the initial email

        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_user(self):
        username = self.cleaned_data.get('user')

        # If the username is not changing, it's valid
        if username == self.user_instance.username:
            return username

        # Check if the new username already exists
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("This username is already taken. Please choose another one.")
        return username

    def save(self, commit=True):
        # Get the MemberDetail instance
        instance = super().save(commit=False)

        # Update the logged-in user's username and email
        self.user_instance.username = self.cleaned_data.get('user')  # Update username
        self.user_instance.email = self.cleaned_data.get('email')  # Update email

        # Save the changes
        if commit:
            self.user_instance.save()  # Save the updated User instance
            instance.save()  # Save the MemberDetail instance
        return instance


