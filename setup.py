""" setup.py for setuptools """

import setuptools

with open("README.md", encoding="utf-8") as readme:
    long_description = readme.read()

requires = ["pandas", "tabulate", "colorlog", "packageurl-python"]

setuptools.setup(
    name="sbomnix",
    version="0.1.0",
    description="Python script that generates SBOMs from nix packages",
    url="https://github.com/tiiuae/sbomnix",
    author="Unikie",
    author_email="henri.rosten@unikie.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    install_requires=requires,
    license="MIT",
    classifiers=[  # See:https://pypi.org/classifiers/
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
    ],
    keywords="SBOM",
    packages=setuptools.find_packages(include=["sbomnix", "sbomnix.*"]),
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "sbomnix = sbomnix.sbomnix:main",
        ]
    },
)
