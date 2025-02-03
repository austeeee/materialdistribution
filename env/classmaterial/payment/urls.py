from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
# Use absolute import path
from django.apps import apps
authentication_views = apps.get_app_config('authentication').module.views

urlpatterns = [
    path('buy_material/<int:material_id>/', authentication_views.buy_material, name='buy_material'),
    ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
