"""Cloudsneeker routes.

Mounted under ``/api/v1/`` by a single hook in ``config/urls.py``. Every
route here lives under the ``cloudsneeker/`` prefix so it can never collide
with an upstream path.
"""

from cloudsneeker_api.views import BrandView
from django.urls import path

urlpatterns = [
    path("cloudsneeker/brand", BrandView.as_view(), name="cloudsneeker-brand"),
]
