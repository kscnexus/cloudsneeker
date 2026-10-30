# Operator console, Phase 1: platform operators, plans, one subscription per
# tenant, subscription history, daily usage snapshots, the operator audit
# trail, the seeded plan catalogue (existing tenants move to the unlimited
# ``legacy`` plan, so nothing changes for them) and the daily usage task.
#
# These tables are not row-level security protected; the application reads
# them through the admin connection. The tenant-scoped database user only
# gets SELECT and DELETE on the tables that reference a tenant or a user, so
# deleting a tenant or a user can cascade to them.

import uuid

import django.db.models.deletion
from api.db_utils import DB_PROWLER_USER
from cloudsneeker_api.services import plan_catalog
from django.conf import settings
from django.db import migrations, models

DAILY_TASK_NAME = "cloudsneeker-operator-daily"
DAILY_INTERVAL_DAYS = 1

CASCADE_TABLES = (
    "cloudsneeker_platform_operators",
    "cloudsneeker_subscriptions",
    "cloudsneeker_subscription_events",
    "cloudsneeker_usage_snapshots",
)


def seed_catalogue(apps, schema_editor):
    alias = schema_editor.connection.alias
    Plan = apps.get_model("cloudsneeker_api", "Plan")
    Subscription = apps.get_model("cloudsneeker_api", "Subscription")
    SubscriptionEvent = apps.get_model("cloudsneeker_api", "SubscriptionEvent")
    Tenant = apps.get_model("api", "Tenant")
    plan_catalog.seed_plans(Plan, using=alias)
    plan_catalog.seed_subscriptions(
        Tenant, Subscription, Plan, SubscriptionEvent, using=alias
    )


def unseed_catalogue(apps, schema_editor):
    # The tables are dropped by the reverse of the CreateModel operations.
    pass


def create_daily_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=DAILY_INTERVAL_DAYS,
        period="days",
    )
    PeriodicTask.objects.update_or_create(
        name=DAILY_TASK_NAME,
        defaults={
            "task": DAILY_TASK_NAME,
            "interval": schedule,
            "enabled": True,
        },
    )


def delete_daily_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=DAILY_TASK_NAME).delete()
    IntervalSchedule.objects.filter(
        every=DAILY_INTERVAL_DAYS,
        period="days",
        periodictask__isnull=True,
    ).delete()


GRANT_SQL = "\n".join(
    f"GRANT SELECT, DELETE ON TABLE {table} TO {DB_PROWLER_USER};"
    for table in CASCADE_TABLES
)
REVOKE_SQL = "\n".join(
    f"REVOKE SELECT, DELETE ON TABLE {table} FROM {DB_PROWLER_USER};"
    for table in CASCADE_TABLES
)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0013_finding_triage"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="PlatformOperator",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "role",
                    models.CharField(
                        choices=plan_catalog.OPERATOR_ROLE_CHOICES,
                        default="read_only",
                        max_length=16,
                    ),
                ),
                ("active", models.BooleanField(default=True)),
                (
                    "granted_by",
                    models.CharField(blank=True, default="", max_length=254),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_platform_operator",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_platform_operators",
            },
        ),
        migrations.CreateModel(
            name="Plan",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("code", models.SlugField(unique=True)),
                ("name", models.CharField(max_length=100)),
                ("description", models.TextField(blank=True, default="")),
                ("features", models.JSONField(blank=True, default=list)),
                ("limits", models.JSONField(blank=True, default=dict)),
                ("is_public", models.BooleanField(default=True)),
                ("sort_order", models.IntegerField(default=100)),
            ],
            options={
                "db_table": "cloudsneeker_plans",
                "ordering": ["sort_order", "code"],
            },
        ),
        migrations.CreateModel(
            name="Subscription",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "status",
                    models.CharField(
                        choices=plan_catalog.STATUS_CHOICES,
                        default="active",
                        max_length=16,
                    ),
                ),
                ("starts_at", models.DateTimeField(blank=True, null=True)),
                ("ends_at", models.DateTimeField(blank=True, null=True)),
                ("trial_ends_at", models.DateTimeField(blank=True, null=True)),
                ("seats", models.PositiveIntegerField(blank=True, null=True)),
                ("feature_overrides", models.JSONField(blank=True, default=dict)),
                ("limit_overrides", models.JSONField(blank=True, default=dict)),
                (
                    "billing_source",
                    models.CharField(
                        choices=plan_catalog.BILLING_SOURCE_CHOICES,
                        default="manual",
                        max_length=32,
                    ),
                ),
                (
                    "external_customer_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                ("notes", models.TextField(blank=True, default="")),
                (
                    "plan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="subscriptions",
                        to="cloudsneeker_api.plan",
                    ),
                ),
                (
                    "tenant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_subscription",
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_subscriptions",
                "indexes": [
                    models.Index(fields=["status"], name="cs_subscription_status_idx"),
                    models.Index(fields=["ends_at"], name="cs_subscription_ends_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="SubscriptionEvent",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("action", models.CharField(max_length=32)),
                ("source", models.CharField(default="operator", max_length=32)),
                ("changes", models.JSONField(blank=True, default=dict)),
                ("actor_id", models.UUIDField(blank=True, null=True)),
                (
                    "actor_email",
                    models.CharField(blank=True, default="", max_length=254),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_subscription_events",
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_subscription_events",
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "-inserted_at"],
                        name="cs_sub_event_tenant_ins_idx",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="UsageSnapshot",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("date", models.DateField()),
                ("counts", models.JSONField(blank=True, default=dict)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_usage_snapshots",
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_usage_snapshots",
                "indexes": [
                    models.Index(fields=["date"], name="cs_usage_snapshot_date_idx"),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("tenant", "date"),
                        name="unique_cs_usage_snapshot_day",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="OperatorAuditEvent",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("actor_id", models.UUIDField(blank=True, null=True)),
                (
                    "actor_email",
                    models.CharField(blank=True, default="", max_length=254),
                ),
                (
                    "actor_role",
                    models.CharField(blank=True, default="", max_length=16),
                ),
                ("action", models.CharField(max_length=100)),
                ("tenant_id", models.UUIDField(blank=True, null=True)),
                (
                    "target_type",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "target_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                ("changed_fields", models.JSONField(blank=True, default=list)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "ip_address",
                    models.GenericIPAddressField(blank=True, null=True),
                ),
                (
                    "user_agent",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                (
                    "request_id",
                    models.CharField(blank=True, default="", max_length=64),
                ),
            ],
            options={
                "db_table": "cloudsneeker_operator_audit_events",
                "indexes": [
                    models.Index(fields=["-inserted_at"], name="cs_op_audit_ins_idx"),
                    models.Index(
                        fields=["tenant_id", "-inserted_at"],
                        name="cs_op_audit_tenant_ins_idx",
                    ),
                ],
            },
        ),
        migrations.RunSQL(GRANT_SQL, reverse_sql=REVOKE_SQL),
        migrations.RunPython(seed_catalogue, unseed_catalogue),
        migrations.RunPython(create_daily_task, delete_daily_task),
    ]
