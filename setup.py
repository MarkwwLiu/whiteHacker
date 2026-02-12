"""Setup script for WhiteHats Security Testing Framework."""

from setuptools import setup, find_packages
from pathlib import Path

readme = Path(__file__).parent / "README.md"
long_description = readme.read_text(encoding="utf-8") if readme.exists() else ""

setup(
    name="whitehats",
    version="1.0.0",
    description="Automated White Hat Security Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="WhiteHats Team",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests", "tests.*", "test_cases", "test_cases.*"]),
    include_package_data=True,
    package_data={
        "whitehats": ["payloads/*.txt"],
    },
    install_requires=[
        "requests>=2.31.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
        "urllib3>=2.0.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "whitehats=whitehats.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
