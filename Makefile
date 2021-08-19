
tests:
	pytest -s

coverage-tests:
	coverage run --rcfile=tests\.coveragerc -m pytest

coverage-unittests:
	coverage run --rcfile=tests\.coveragerc -m pytest tests/unit_tests

coverage-report:
	coverage report -m
	coverage html

format:
	autoflake --remove-all-unused-imports --ignore-init-module-imports --in-place --recursive .
	black --target-version py36 . -l 96
	isort -l 96 -e .

mypy:
	python -m mypy requests_oauth2client --show-error-codes

sdist:
	python setup.py sdist

release: format sdist

release-patch: format
	bump2version patch VERSION
	git push

release-minor: format
	bump2version minor VERSION
	git push

release-major: format
	bump2version major VERSION
	git push

.PHONY: tests mypy