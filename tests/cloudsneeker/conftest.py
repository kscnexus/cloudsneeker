import pytest

from cloudsneeker import brand as brand_module
from cloudsneeker import sdk
from cloudsneeker.brand import Brand, load_brand


@pytest.fixture(autouse=True)
def default_brand(monkeypatch: pytest.MonkeyPatch) -> Brand:
    """Run Cloudsneeker tests against the shipped defaults.

    ``tests/conftest.py`` loads the brand with upstream-compatible overrides so
    upstream suites keep passing. Tests in this package assert the real product
    identity, so the module-level ``brand`` objects are swapped for the defaults.
    """
    shipped = load_brand({})
    monkeypatch.setattr(brand_module, "brand", shipped)
    monkeypatch.setattr(sdk, "brand", shipped)
    return shipped


@pytest.fixture
def brand(default_brand: Brand) -> Brand:
    """Short alias for the shipped brand."""
    return default_brand
