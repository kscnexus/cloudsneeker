"""Signal receivers that connect Cloudsneeker behavior to upstream models.

Connected in :meth:`CloudsneekerApiConfig.ready`, so upstream files stay
untouched.
"""

from __future__ import annotations

from django.db.models.signals import post_save


def _invitation_saved(sender, instance, created, **kwargs):
    # The first administrator of an organization created in the operator
    # console becomes its owner when they accept (sign-up or existing user).
    if created:
        return
    from cloudsneeker_api.services.customers import promote_sole_member

    promote_sole_member(instance)


def connect() -> None:
    from api.models import Invitation

    post_save.connect(
        _invitation_saved,
        sender=Invitation,
        dispatch_uid="cloudsneeker_api.invitation_promote_sole_member",
    )
