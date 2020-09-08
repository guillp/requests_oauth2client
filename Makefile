
tests:
	pytest -s

coverage-tests:
	coverage run --rcfile=tests\.coveragerc -m pytest

coverage-report:
	coverage report -m
	coverage html

format:
	autoflake --remove-all-unused-imports --ignore-init-module-imports --in-place --recursive .
	black --target-version py36 . -l 96
	isort -l 96 -e .

mypy:
	python -m mypy requests_oauth2client --show-error-codes

lock:
	pipenv run pip freeze > requirements.txt

sdist:
	python setup.py sdist

release: format lock sdist

.PHONY: tests mypy