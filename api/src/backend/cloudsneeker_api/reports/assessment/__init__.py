"""Security assessment reports.

Four report types share one pipeline:

1. ``collect`` reads scanner records for the scope (database access).
2. ``accuracy`` normalizes status polarity, removes duplicates, and checks
   that totals reconcile (pure functions).
3. ``scoring``, ``recommend``, and ``roadmap`` turn the clean findings into
   scores, recommendations, and a remediation plan (pure functions).
4. ``builder`` assembles the report content for one report type; ``ai`` adds
   the optional Seeker AI insights, kept apart from scanner facts.
5. ``render_pdf`` and ``export`` produce the files; ``quality`` checks the
   content and the rendered layout before a report is marked distributable.
"""

ENGINE_VERSION = "2.0"
