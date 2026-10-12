from cloudsneeker_api.brand import brand
from django.apps import AppConfig


class CloudsneekerApiConfig(AppConfig):
    """Django app that carries Cloudsneeker-only API behavior.

    Everything that is not a thin hook into an upstream file lives in this
    app: new endpoints under ``/api/v1/cloudsneeker/``, new tables with the
    ``cloudsneeker_`` prefix, and their tests.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "cloudsneeker_api"
    label = "cloudsneeker_api"
    verbose_name = brand.name
