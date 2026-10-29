"""Cloudsneeker reporting engine.

* ``catalog`` lists the report types and validates their parameters.
* ``data`` assembles one typed ``ReportData`` per report type from the shared
  Scan / Finding / Compliance tables and the Cloudsneeker Custodian runs.
* ``render`` turns a ``ReportData`` into PDF, XLSX, CSV, or JSON bytes.
* ``runs``, ``schedule``, ``share``, and ``delivery`` hold the job, beat,
  share-link, and email services used by the views and Celery tasks.
"""
