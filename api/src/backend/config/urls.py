from api.health import LivenessView, ReadinessView
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("api.v1.urls")),
    path("api/v1/", include("cloudsneeker_api.urls")),  # cloudsneeker-hook
    path("health/live", LivenessView.as_view(), name="health-live"),
    path("health/ready", ReadinessView.as_view(), name="health-ready"),
]
