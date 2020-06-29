import pytest
import requests


@pytest.fixture()
def session():
    return requests.Session()
