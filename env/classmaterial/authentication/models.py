from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.core.validators import FileExtensionValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.utils.timezone import now

from django.core.exceptions import ValidationError


ROLE_CHOICES = [
    ('student', 'Student'),
    ('teacher', 'Teacher'),
]
CLASS_CHOICES = [
    ("Grade 6", "Grade 6"),
    ("Grade 7", "Grade 7"),
    ("Grade 8", "Grade 8"),
    ("Grade 9", "Grade 9"),
    ("Grade 10", "Grade 10"),
    ("B.Sc Physics", "B.Sc Physics"),
    ("B.Sc Chemistry", "B.Sc Chemistry"),
    ]
class User(AbstractUser):
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    email = models.EmailField(unique=True)  # Ensure email uniqueness
    registered_at = models.DateTimeField(auto_now_add=True)  # Automatically set when the user is created

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

class MemberDetail(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="member_detail", unique=True)
    phone_number = models.CharField(max_length=15)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    registered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'authentication_memberdetail'

    def __str__(self):
        return f"{self.user.username} - {self.role}"

    
class MaterialDetail(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    category = models.CharField(max_length=100)
    quantity_available = models.IntegerField()
    target_class = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)  # New price field
    added_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="materials")
    file = models.FileField(
        upload_to='materials/',
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'docx', 'txt', 'pptx'])],
        null=True,
        blank=True
    )

    def __str__(self):
        return f"{self.name} - {self.target_class} (₹{self.price})"
    
class MaterialComment(models.Model):
    material = models.ForeignKey(MaterialDetail, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # Changed to use AUTH_USER_MODEL
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.material.name}"
    
class MaterialRequest(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Delivered', 'Delivered'),
    ]

    material = models.ForeignKey(
        MaterialDetail, 
        on_delete=models.CASCADE, 
        related_name="requests"
    )
    student = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name="material_requests"
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Pending'
    )
    approved_at = models.DateTimeField(
        null=True, 
        blank=True, 
        help_text="Timestamp when the request was approved."
    )
    rejected_at = models.DateTimeField(
        null=True, 
        blank=True, 
        help_text="Timestamp when the request was rejected."
    )
    delivered_at = models.DateTimeField(
        null=True, 
        blank=True, 
        help_text="Timestamp when the material was marked as delivered."
    )
    quantity_requested = models.PositiveIntegerField(
        default=1, 
        help_text="The quantity of material requested by the student."
    )
    notes = models.TextField(
        null=True, 
        blank=True, 
        help_text="Optional notes or comments about the request."
    )
    is_new = models.BooleanField(default=False)  # New field to track status updates

    def approve(self):
        """
        Approve the request and set the approved_at timestamp.
        """
        self.status = 'Approved'
        self.approved_at = now()
        self.save()

    def reject(self):
        """
        Reject the request and set the rejected_at timestamp.
        """
        self.status = 'Rejected'
        self.rejected_at = now()
        self.save()

    def deliver(self):
        if self.status == 'Approved':
            self.status = 'Delivered'
            self.delivered_at = now()
            self.save()
        else:
            raise ValueError("Only approved requests can be marked as delivered.")
        
    def save(self, *args, **kwargs):
        if self.pk:  # Check if it's an existing request
            old_request = MaterialRequest.objects.get(pk=self.pk)
            if old_request.status != self.status:  # If the status has changed
                self.is_new = True  # Mark as new notification
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.student.username} requested {self.material.name} ({self.quantity_requested}) - {self.status}"
@receiver(post_save, sender=User)
def create_member_detail(sender, instance, created, **kwargs):
    from .models import MemberDetail
    if created:
        MemberDetail.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_member_detail(sender, instance, **kwargs):
    from .models import MemberDetail
    instance.member_detail.save()