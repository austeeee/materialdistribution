from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
# Use absolute import path
from django.apps import apps
authentication_views = apps.get_app_config('authentication').module.views


urlpatterns = [
    # Now referencing views from authentication app
    path('material', authentication_views.material, name='material'),
    path('update_material', authentication_views.update_materials_list, name='update_materials_list'),
    path('materials/update/<int:material_id>/', authentication_views.update_material, name='update_material'),
    path('reports', authentication_views.generate_reports, name='generate_reports'),
    path('materials/<int:material_id>/add_comment_admin/', authentication_views.add_comment_admin, name='add_comment_admin'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)