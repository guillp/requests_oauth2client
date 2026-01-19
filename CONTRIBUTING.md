# Contributing

Contributions are welcome, and they are greatly appreciated! Every little bit
helps, and credit will always be given.

You can contribute in many ways:

## Types of Contributions

### Report Bugs

Report bugs at https://github.com/guillp/requests_oauth2client/issues.

If you are reporting a bug, please include:

- Detailed steps to reproduce the bug.
- _Full_ error message whenever there is one
- Your Python version, operating system name and version.
- Any details about your local setup that might be helpful in troubleshooting.

### Fix Bugs

Look through the GitHub issues for bugs. Anything tagged with "bug" and "help
wanted" is open to whoever wants to implement it.

### Implement Features

Look through the GitHub issues for features. Anything tagged with "enhancement"
and "help wanted" is open to whoever wants to implement it.

### Write Documentation

`requests_oauth2client` could always use more documentation, whether as part of the
official requests_oauth2client docs, in docstrings, or even on the web in blog posts,
articles, and such.

### Submit Feedback

The best way to send feedback is to file an issue at https://github.com/guillp/requests_oauth2client/issues.

If you are proposing a feature:

- Explain in detail how it would work.
- Keep the scope as narrow as possible, to make it easier to implement.
- Remember that this is a volunteer-driven project, and that contributions
  are welcome :)

## Get Started!

Ready to contribute? Here's how to set up `requests_oauth2client` for local development.

1. Fork the `requests_oauth2client` repo on GitHub.
1. Clone your fork locally

```
$ git clone https://github.com/<your_github_username_here>/requests_oauth2client.git
```

3. Ensure [uv](https://docs.astral.sh/uv/) is installed.
1. Install dependencies and start your virtualenv:

```
$ uv sync --all-extras
```

5. Create a branch for local development:

```
$ git checkout -b name-of-your-bugfix-or-feature
```

Now you can make your changes locally.

6. When you're done making changes, check that your changes pass the
   tests, including testing other Python versions, with tox:

```
$ tox
```

7. Commit your changes and push your branch to GitHub:

```
$ git add .
$ git commit -m "Your detailed description of your changes."
$ git push origin name-of-your-bugfix-or-feature
```

8. Submit a pull request through the GitHub website.

## Pull Request Guidelines

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
1. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.md.
1. The pull request should work for Python 3.8+ and for PyPy. Check
   https://github.com/guillp/requests_oauth2client/actions
   and make sure that the tests pass for all supported Python versions.

## Tips

```
$ pytest tests.test_client_credentials
```

To run a subset of tests.

## Deploying

A reminder for the maintainers on how to deploy.
Make sure all your changes are committed (including an entry in HISTORY.md).
Then run:

```
$ uv version --bump path # possible: major / minor / patch
$ git push
$ git push --tags
```

Travis will then deploy to PyPI if tests pass.
