import pytest


def pytest_addoption(parser):
    """Adds custom command-line options for certificate paths."""
    parser.addoption(
        "--root-ca", action="store", default=None, help="Path to the Root CA certificate file"
    )
    parser.addoption(
        "--intermediate-ca", action="store", default=None, help="Path to the Intermediate CA certificate file"
    )
    parser.addoption(
        "--end-entity", action="store", default=None, help="Path to the End-Entity certificate file"
    )


@pytest.fixture
def root_ca_path(request):
    """Fixture to get the Root CA path from command line option."""
    path = request.config.getoption("--root-ca")
    if path is None:
        pytest.skip("Test requires --root-ca option")
    return path


@pytest.fixture
def intermediate_ca_path(request):
    """Fixture to get the Intermediate CA path from command line option."""
    path = request.config.getoption("--intermediate-ca")
    if path is None:
        pytest.skip("Test requires --intermediate-ca option")
    return path


@pytest.fixture
def end_entity_path(request):
    """Fixture to get the End-Entity path from command line option."""
    path = request.config.getoption("--end-entity")
    if path is None:
        pytest.skip("Test requires --end-entity option")
    return path
