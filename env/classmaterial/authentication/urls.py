
from django.contrib import admin
from django.urls import path,include
from . import views
from django.contrib.auth import views as auth_views
from .views import CustomLoginView
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('',views.home,name='home'),
    path('home',views.home,name='home'),
    path('register',views.register,name='register'),
    path('custom_password_reset/', views.custom_password_reset, name='custom_password_reset'),
    path('custom_password_reset_confirm/<uidb64>/<token>/', views.custom_password_reset_confirm, name='custom_password_reset_confirm'),
    path('login', CustomLoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('student', views.student,name='student'),
    path('layout', views.layout,name='layout'),
    path('junior', views.junior,name='junior'),
    path('admin', views.admin,name='admin'),
    path('class_choices', views.class_choices_view, name='class_choices'),
    path('student/<str:target_class>/', views.student, name='student'),
    path('teacher-choices/', views.teacher_choices_view, name='teacher_choices'),
    path('teacher', views.teacher_page_view, name='teacher'), 
    path('add_comment/<int:material_id>/', views.add_comment, name='add_comment'),
    path('student/<str:target_class>/', views.student, name='student'),
    path('add_comment/<int:material_id>/', views.add_comment, name='add_comment'),
    path('materials/<int:material_id>/add_comment_admin/', views.add_comment_admin, name='add_comment_admin'),
    path('addmaterial', views.add_material_view, name='addmaterial'),
    path('remove-member/<int:user_id>/', views.remove_member, name='remove_member'),
    path('send_request/<int:material_id>/', views.send_request, name='send_request'),
    path('requests/', views.teacher_request, name='teacher_requests'),
    path('requests/<int:request_id>/', views.teacher_request, name='teacher_request_detail'),
    path('teacher/requests/approve/<int:request_id>/', views.approve_request, name='approve_request'),
    path('teacher/requests/reject/<int:request_id>/', views.reject_request, name='reject_request'),
    path('my_requests/', views.my_requests, name='my_requests'),
    path('approve_request/<int:request_id>/', views.approve_request, name='approve_request'),
    path('reject_request/<int:request_id>/', views.reject_request, name='reject_request'),
    path('about', views.about, name='about'),
    path('services', views.services, name='services'),
    path('contact', views.contact, name='contact'),
    path('profile/', views.profile_view, name='profile'),
    path('material', views.material, name='material'),
    path('requests/', views.teacher_request, name='requests'), 
    path('buy_material/<int:material_id>/', views.buy_material, name='buy_material'),
    # urls.py
    path('requests/<int:request_id>/', views.teacher_request, name='requests'),

    # List all materials (Update Materials List page)
    path('update_material', views.update_materials_list, name='update_materials_list'),

    # Update a specific material
    path('materials/update/<int:material_id>/', views.update_material, name='update_material'),

    # Remove a specific material
    path('materials/remove/<int:material_id>/', views.remove_material, name='remove_material'),
    path('reports', views.generate_reports, name='generate_reports'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)