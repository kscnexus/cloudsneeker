"""Build and release tooling for Cloudsneeker.

``rebrand.py`` rewrites display copy in a build tree, ``brand_audit.py`` fails a
build when an upstream brand string survives. Both run on the standard library
only so they work before project dependencies are installed.
"""
