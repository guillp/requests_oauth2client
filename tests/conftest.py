from __future__ import annotations

import pytest
import requests


@pytest.fixture()
def session():
    return requests.Session()
