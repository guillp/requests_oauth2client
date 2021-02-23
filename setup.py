from setuptools import find_packages, setup

__title__ = "requests_oauth2client"
__description__ = "An OAuth 2.0 client library for Python, with requests integration."
__url__ = "https://github.com/guillp/requests_oauth2client"
__version__ = "0.9.2"
__author__ = "Guillaume Pujol"
__author_email__ = "guill.p.linux@gmail.com"
__license__ = "Apache 2.0"
__copyright__ = "Copyright 2020 Guillaume Pujol"

with open("README.rst", "rt") as finput:
    readme = finput.read()

with open("requirements.txt", "rt") as finput:
    requires = [line.strip() for line in finput.readlines()]

setup(
    name=__title__,
    version=__version__,
    description=__description__,
    long_description=readme,
    long_description_content_type="text/x-rst",
    author=__author__,
    author_email=__author_email__,
    url=__url__,
    packages=find_packages(exclude=("tests",)),
    package_data={"": ["LICENSE", "requirements.txt"]},
    package_dir={"requests_oauth2client": "requests_oauth2client"},
    include_package_data=True,
    python_requires=">=3.6",
    install_requires=requires,
    license=__license__,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    project_urls={"Source": "https://github.com/guillp/requests_oauth2client",},
)
