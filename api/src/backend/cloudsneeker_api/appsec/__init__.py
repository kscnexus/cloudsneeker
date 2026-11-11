"""Application security posture management (ASPM) engine.

Pure modules (no Django import, unit-tested without a database):

* ``capabilities``: scan engine version, target and scanner matrix, feature
  coverage. The API serves it so the UI only offers valid combinations.
* ``options``: scan option validation and argv construction.
* ``parser``: scan report to normalized findings and components.
* ``risk``: explainable priority score.
* ``sbom``: component diff and CycloneDX / SPDX documents.
* ``failures``: exit code and stderr classification.

Database modules: ``engine`` (execution), ``lifecycle`` (finding
reconciliation), ``inventory`` (SBOM storage), ``queries`` (dashboards).
"""
