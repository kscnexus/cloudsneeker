"""Grant, revoke and list platform operators.

The only way to create an operator: there are no default operator users.

    python manage.py cloudsneeker_operator grant you@company.com --role owner
    python manage.py cloudsneeker_operator revoke you@company.com
    python manage.py cloudsneeker_operator list

The user must already exist (sign up or be invited first). Every change is
written to the operator audit log with the actor ``cli``.
"""

from __future__ import annotations

from cloudsneeker_api.services import plan_catalog as catalog
from django.core.management.base import BaseCommand, CommandError

CLI_ACTOR = "cli"


class Command(BaseCommand):
    help = "Grant, revoke or list operator console access by email."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        grant = sub.add_parser("grant", help="Grant or change an operator role.")
        grant.add_argument("email")
        grant.add_argument(
            "--role",
            default=catalog.OPERATOR_ROLE_READ_ONLY,
            choices=[value for value, _ in catalog.OPERATOR_ROLE_CHOICES],
        )
        revoke = sub.add_parser("revoke", help="Deactivate an operator.")
        revoke.add_argument("email")
        sub.add_parser("list", help="List operators.")

    def handle(self, *args, **options):
        action = options["action"]
        if action == "grant":
            return self._grant(options["email"], options["role"])
        if action == "revoke":
            return self._revoke(options["email"])
        return self._list()

    @staticmethod
    def _db() -> str:
        from api.db_router import MainRouter

        return MainRouter.admin_db

    def _user(self, email: str):
        from api.models import User

        user = User.objects.using(self._db()).filter(email__iexact=email).first()
        if user is None:
            raise CommandError(
                f"No user with email {email}. Sign up or invite the user first."
            )
        return user

    def _audit(self, action: str, operator, changed: list[str]) -> None:
        from cloudsneeker_api.models import OperatorAuditEvent

        OperatorAuditEvent.objects.using(self._db()).create(
            actor_email=CLI_ACTOR,
            action=action,
            target_type="platform_operator",
            target_id=str(operator.id),
            changed_fields=changed,
            metadata={"email": operator.user.email, "role": operator.role},
        )

    def _grant(self, email: str, role: str) -> None:
        from cloudsneeker_api.models import PlatformOperator

        user = self._user(email)
        operator, created = PlatformOperator.objects.using(self._db()).get_or_create(
            user=user,
            defaults={"role": role, "active": True, "granted_by": CLI_ACTOR},
        )
        changed = ["role", "active"] if created else []
        if not created:
            if operator.role != role:
                operator.role = role
                changed.append("role")
            if not operator.active:
                operator.active = True
                changed.append("active")
            if changed:
                operator.granted_by = CLI_ACTOR
                operator.save(using=self._db())
        if changed:
            self._audit("operator.grant", operator, changed)
        self.stdout.write(
            self.style.SUCCESS(
                f"{user.email} is an operator with role {operator.role}."
            )
        )

    def _revoke(self, email: str) -> None:
        from cloudsneeker_api.models import PlatformOperator

        user = self._user(email)
        operator = PlatformOperator.objects.using(self._db()).filter(user=user).first()
        if operator is None or not operator.active:
            self.stdout.write(f"{user.email} is not an active operator.")
            return
        operator.active = False
        operator.save(using=self._db())
        self._audit("operator.revoke", operator, ["active"])
        self.stdout.write(
            self.style.SUCCESS(f"Operator access revoked for {user.email}.")
        )

    def _list(self) -> None:
        from cloudsneeker_api.models import PlatformOperator

        operators = (
            PlatformOperator.objects.using(self._db())
            .select_related("user")
            .order_by("user__email")
        )
        if not operators:
            self.stdout.write("No operators.")
            return
        for operator in operators:
            state = "active" if operator.active else "revoked"
            self.stdout.write(f"{operator.user.email}\t{operator.role}\t{state}")
