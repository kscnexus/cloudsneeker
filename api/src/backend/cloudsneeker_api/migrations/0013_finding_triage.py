# Finding triage (EB-010): status per finding UID and its note thread.

import uuid

import api.rls
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

STATUS_CHOICES = [
    ("open", "Open"),
    ("under_review", "Under review"),
    ("remediating", "Remediating"),
    ("resolved", "Resolved"),
    ("risk_accepted", "Risk accepted"),
    ("false_positive", "False positive"),
    ("reopened", "Reopened"),
]

SOURCE_CHOICES = [
    ("manual", "Manual"),
    ("bulk", "Bulk"),
    ("integration", "Integration"),
    ("automation", "Automation"),
]


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0012_audit_log"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="FindingTriage",
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
                ("finding_uid", models.CharField(max_length=300)),
                (
                    "status",
                    models.CharField(
                        choices=STATUS_CHOICES, default="open", max_length=32
                    ),
                ),
                ("status_changed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "source",
                    models.CharField(
                        choices=SOURCE_CHOICES, default="manual", max_length=32
                    ),
                ),
                ("check_id", models.CharField(blank=True, default="", max_length=100)),
                (
                    "assignee",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_assigned_finding_triages",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_finding_triages",
                        to="api.provider",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_updated_finding_triages",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_finding_triages",
                "abstract": False,
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "status"],
                        name="cs_triage_tenant_status_idx",
                    ),
                    models.Index(
                        fields=["tenant_id", "check_id"],
                        name="cs_triage_tenant_check_idx",
                    ),
                    models.Index(
                        fields=["tenant_id", "provider_id"],
                        name="cs_triage_tenant_provider_idx",
                    ),
                    models.Index(
                        fields=["tenant_id", "-updated_at"],
                        name="cs_triage_tenant_updated_idx",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="FindingTriageNote",
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
                ("body", models.TextField(max_length=4000)),
                ("status", models.CharField(blank=True, default="", max_length=32)),
                (
                    "author",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_finding_triage_notes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
                (
                    "triage",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notes",
                        to="cloudsneeker_api.findingtriage",
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_finding_triage_notes",
                "abstract": False,
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "triage_id", "-inserted_at"],
                        name="cs_triage_note_tenant_ins_idx",
                    ),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="findingtriage",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_findingtriage",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="findingtriage",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "finding_uid"),
                name="unique_cs_finding_triage_uid_per_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="findingtriagenote",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_findingtriagenote",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
