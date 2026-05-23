"""Setup configuration for Blockchain Forensics Agent."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="blockchain-forensics-agent",
    version="1.0.0",
    author="Blockchain Forensics Team",
    description="Advanced blockchain forensics platform with 6 AI agents powered by MiMo V2.5",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/marcelo35y/blockchain-forensics-agent",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "networkx>=3.0",
        "numpy>=1.24",
        "requests>=2.28",
        "click>=8.0",
        "rich>=13.0",
        "jinja2>=3.1",
        "pydantic>=2.0",
        "scipy>=1.10",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "pytest-asyncio>=0.21",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "blockchain-forensics=src.main:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
)
