"""
Setup configuration for Argus shell package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="argus-shell",
    version="1.0.0",
    author="Argus Team",
    description="A security-focused Unix shell with audit logging, risk scoring, and suspicious activity detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/argus",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: BSD",
        "Environment :: Console",
        "Topic :: System :: Shells",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "argus=argus.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
