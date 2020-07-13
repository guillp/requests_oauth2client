
tests:
	pytest -s

coverage-tests:
	coverage run --rcfile=tests\.coveragerc -m pytest

coverage-report:
	coverage report -m
	coverage html

format:
	black --target-version py36 . -l 96
	isort -l 96 -e -y

mypy:
	python -m mypy requests_oauth2client

lock:
	pipenv lock -r > requirements.txt
	pipenv lock -r -d > requirements-dev.txt

sdist:
	python setup.py sdist

release: format lock sdist

.PHONY: tests mypy