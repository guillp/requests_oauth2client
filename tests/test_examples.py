import pytest
from pytest_examples import CodeExample, EvalExample, find_examples


@pytest.mark.parametrize("example", find_examples("README.md"), ids=str)
def test_readme(example: CodeExample, eval_example: EvalExample) -> None:
    eval_example.set_config(line_length=120, ruff_ignore=["D", "E402", "ERA001", "F", "S", "T"])
    if eval_example.update_examples:
        eval_example.format(example)
    else:
        eval_example.lint(example)
