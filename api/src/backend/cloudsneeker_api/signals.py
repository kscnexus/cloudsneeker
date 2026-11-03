"""Signal receivers that connect Cloudsneeker behavior to upstream models.

Connected in :meth:`CloudsneekerApiConfig.ready`, so upstream files stay
untouched.
"""

from __future__ import annotations

from django.db import transaction
from django.db.models.signals import post_save


def _invitation_saved(sender, instance, created, **kwargs):
    # The first administrator of an organization created in the operator
    # console becomes its owner when they accept (sign-up or existing user).
    if created:
        return
    from cloudsneeker_api.services.customers import promote_sole_member

    promote_sole_member(instance)


def _user_saved(sender, instance, created, using=None, **kwargs):
    # A new user on CLOUDSNEEKER_BOOTSTRAP_OPERATOR_EMAILS becomes the first
    # operator owner. After commit, so the operator row can reference the user
    # from the admin connection; robust, so a failure never breaks sign-up.
    if not created:
        return
    from cloudsneeker_api.services import bootstrap_operators

    if not bootstrap_operators.bootstrap_emails():
        return
    transaction.on_commit(
        lambda: bootstrap_operators.grant_if_bootstrap(instance),
        using=using,
        robust=True,
    )


def connect() -> None:
    from api.models import Invitation, User

    post_save.connect(
        _invitation_saved,
        sender=Invitation,
        dispatch_uid="cloudsneeker_api.invitation_promote_sole_member",
    )
    post_save.connect(
        _user_saved,
        sender=User,
        dispatch_uid="cloudsneeker_api.user_bootstrap_operator",
    )
