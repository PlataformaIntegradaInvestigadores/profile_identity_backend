from django.urls import path

from .views import HealthLiveView


urlpatterns = [
    path("", HealthLiveView.as_view(), name="health-live"),
]
