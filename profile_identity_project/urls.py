from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from identity.views import ValidateTokenView


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("identity.urls")),
    path("internal/auth/validate-token/", ValidateTokenView.as_view(), name="validate-token"),
    path("health/live/", include("identity.health_urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
