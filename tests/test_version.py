import dementor


def test_version_dev():
    """
    Smoke test to verify that the package version contains 'dev'.
    """
    assert "dev" in dementor.__version__
