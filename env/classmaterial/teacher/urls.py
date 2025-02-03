from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
# Use absolute import path
from django.apps import apps
authentication_views = apps.get_app_config('authentication').module.views

urlpatterns = [
    path('requests/', authentication_views.teacher_request, name='teacher_requests'),
    path('requests/<int:request_id>/', authentication_views.teacher_request, name='teacher_request_detail'),
    path('requests/', authentication_views.teacher_request, name='requests'), 
    path('requests/<int:request_id>/', authentication_views.teacher_request, name='requests'),
    ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
