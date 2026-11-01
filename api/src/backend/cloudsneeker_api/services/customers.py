"""Customer onboarding from the operator console.

:func:`create_customer` makes a new organization (tenant) with an ``admin``
role, a pending invitation for the customer's administrator and a
subscription, in one transaction. The operator never becomes a member, so
the customer's data stays out of the operator's own organization list.

Invited users join as members upstream. :func:`promote_sole_member` (wired to
``Invitation`` saves in :mod:`cloudsneeker_api.signals`) makes the accepting
user the owner when they are the organization's only member, which only
happens for organizations created here: any other organization already had a
member who sent the invitation.

Writes go through ``MainRouter.admin_db`` because the tenant does not exist in
any session yet.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from cloudsneeker_api.services import entitlements as service
from cloudsneeker_api.services import plan_catalog as catalog

logger = logging.getLogger(__name__)

ADMIN_ROLE_NAME = "admin"
# Statuses a new customer can start in.
INITIAL_STATUSES = frozenset({catalog.STATUS_TRIAL, catalog.STATUS_ACTIVE})
SUBSCRIPTION_FIELDS = (
    "plan",
    "status",
    "starts_at",
    "ends_at",
    "trial_ends_at",
    "seats",
    "billing_source",
    "external_customer_id",
    "notes",
)


class CustomerError(ValueError):
    """An invalid onboarding request (shown to the operator as a 400)."""


class CustomerConflict(CustomerError):
    """The request does not fit the organization's current state (409)."""


@dataclass(frozen=True)
class CreatedCustomer:
    tenant: Any
    subscription: Any
    invitation: Any


def _admin_db() -> str:
    from api.db_router import MainRouter

    return MainRouter.admin_db


def _subscription_values(data: dict) -> dict:
    values = {name: data[name] for name in SUBSCRIPTION_FIELDS if name in data}
    values.setdefault("status", catalog.STATUS_ACTIVE)
    if values["status"] not in INITIAL_STATUSES:
        raise CustomerError("A new customer starts as 'trial' or 'active'.")
    if not values.get("plan"):
        values.pop("plan", None)
    try:
        # Validates plan, dates and the rest before anything is written.
        service.clean_subscription_changes(values)
    except service.SubscriptionError as error:
        raise CustomerError(str(error)) from None
    return values


def _admin_role(tenant_id):
    from api.models import Role

    role, _ = Role.objects.using(_admin_db()).get_or_create(
        tenant_id=tenant_id,
        name=ADMIN_ROLE_NAME,
        defaults={
            **dict.fromkeys(Role.PERMISSION_FIELDS, True),
            "unlimited_visibility": True,
        },
    )
    return role


def _invite_admin(tenant_id, email: str, inviter):
    from api.models import Invitation, InvitationRoleRelationship

    alias = _admin_db()
    invitation = Invitation.objects.using(alias).create(
        tenant_id=tenant_id,
        email=email,
        inviter_id=getattr(inviter, "id", None),
    )
    InvitationRoleRelationship.objects.using(alias).create(
        tenant_id=tenant_id, invitation=invitation, role=_admin_role(tenant_id)
    )
    return invitation


def create_customer(
    *, name: str, admin_email: str, inviter, subscription: dict | None = None
) -> CreatedCustomer:
    """Create the organization, its admin role, invitation and subscription."""
    from api.models import Tenant
    from django.db import transaction

    values = _subscription_values(subscription or {})
    alias = _admin_db()
    with transaction.atomic(using=alias):
        tenant = Tenant.objects.using(alias).create(name=name)
        invitation = _invite_admin(tenant.id, admin_email, inviter)
        service.ensure_subscription(str(tenant.id))
        subscription_row, _ = service.update_subscription(
            str(tenant.id),
            values,
            actor_id=str(getattr(inviter, "id", "") or ""),
            actor_email=getattr(inviter, "email", "") or "",
        )
    return CreatedCustomer(tenant, subscription_row, invitation)


def member_count(tenant_id) -> int:
    from api.models import Membership

    return Membership.objects.using(_admin_db()).filter(tenant_id=tenant_id).count()


def pending_invitations(tenant_id) -> list:
    from api.models import Invitation

    return list(
        Invitation.objects.using(_admin_db())
        .filter(tenant_id=tenant_id, state=Invitation.State.PENDING)
        .order_by("-inserted_at")
    )


def resend_admin_invitation(tenant_id, *, inviter, admin_email: str = ""):
    """Revoke pending invitations and invite the admin again.

    Only for an organization nobody has joined yet: once it has a member,
    that member invites people from inside the organization.
    """
    from api.models import Invitation
    from django.db import transaction

    if member_count(tenant_id):
        raise CustomerConflict(
            "This organization already has members; they invite people from inside it."
        )
    alias = _admin_db()
    with transaction.atomic(using=alias):
        pending = Invitation.objects.using(alias).filter(
            tenant_id=tenant_id, state=Invitation.State.PENDING
        )
        email = admin_email or (
            pending.order_by("-inserted_at").values_list("email", flat=True).first()
            or Invitation.objects.using(alias)
            .filter(tenant_id=tenant_id)
            .order_by("-inserted_at")
            .values_list("email", flat=True)
            .first()
        )
        if not email:
            raise CustomerError("Give the administrator's email.")
        pending.update(state=Invitation.State.REVOKED)
        return _invite_admin(tenant_id, email, inviter)


def promote_sole_member(invitation) -> bool:
    """Make the accepting user owner of an organization they are alone in.

    Returns True when a membership was promoted. Never raises: a failure is
    logged and the user stays a member with the invitation's roles.
    """
    from api.models import Invitation, Membership

    if invitation.state != Invitation.State.ACCEPTED:
        return False
    try:
        alias = _admin_db()
        memberships = list(
            Membership.objects.using(alias).filter(tenant_id=invitation.tenant_id)[:2]
        )
        if len(memberships) != 1:
            return False
        membership = memberships[0]
        if membership.role == Membership.RoleChoices.OWNER:
            return False
        if (membership.user.email or "").lower() != (invitation.email or "").lower():
            return False
        membership.role = Membership.RoleChoices.OWNER
        membership.save(using=alias, update_fields=["role"])
        return True
    except Exception:
        logger.exception(
            "Sole member not promoted tenant=%s invitation=%s",
            invitation.tenant_id,
            invitation.id,
        )
        return False
