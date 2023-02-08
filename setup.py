# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" setup.py for setuptools """

import setuptools

with open("README.md", encoding="utf-8") as readme:
    long_description = readme.read()

requires = [
    "pandas",
    "colorlog",
    "packageurl-python",
    "tabulate",
    "graphviz",
    "reuse",
    "wheel",
]

setuptools.setup(
    name="sbomnix",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
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
    keywords="SBOM",
    packages=["sbomnix", "nixgraph", "scripts.vulnxscan"],
    scripts=["scripts/update-cpedict.sh", "scripts/vulnxscan/osv.py"],
    entry_points={
        "console_scripts": [
            "sbomnix  = sbomnix.main:main",
            "nixgraph = nixgraph.main:main",
            "vulnxscan= scripts.vulnxscan.vulnxscan:main",
        ]
    },
)
