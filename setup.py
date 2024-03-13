# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=missing-function-docstring

""" setup.py for setuptools """

import os.path

import setuptools

with open("README.md", encoding="utf-8") as readme:
    long_description = readme.read()


def project_path(*names):
    return os.path.join(os.path.dirname(__file__), *names)


with open(project_path("VERSION"), encoding="utf-8") as f:
    version = f.read().strip()


requires = [
    "beautifulsoup4",
    "colorlog",
    "graphviz",
    "numpy",
    "pandas",
    "packageurl-python",
    "packaging",
    "reuse",
    "requests",
    "requests-cache",
    "requests-ratelimiter",
    "setuptools",
    "tabulate",
]

setuptools.setup(
    name="sbomnix",
    version=version,
    description="Utility that generates SBOMs from nix packages",
    url="https://github.com/tiiuae/sbomnix",
    author="TII",
    author_email="henri.rosten@unikie.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    install_requires=requires,
    license="Apache-2.0",
    classifiers=[  # See:https://pypi.org/classifiers/
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
    ],
    packages=setuptools.find_namespace_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "sbomnix  = sbomnix.main:main",
            "nixgraph = nixgraph.main:main",
            "nixmeta = nixmeta.main:main",
            "nix_outdated = nixupdate.nix_outdated:main",
            "vulnxscan = vulnxscan.vulnxscan_cli:main",
            "repology_cli = repology.repology_cli:main",
            "repology_cve = repology.repology_cve:main",
            "provenance = provenance.main:main",
        ]
    },
)
