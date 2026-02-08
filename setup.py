from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="clawguard",
    version="0.1.0",
    author="Ramiche Security",
    author_email="security@ramiche.com",
    description="OpenClaw Security Scanner - Protect your AI agents from vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ramiche/clawguard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "rich>=13.0.0",
        "click>=8.1.0",
    ],
    entry_points={
        "console_scripts": [
            "clawguard=clawguard.cli:main",
        ],
    },
    include_package_data=True,
)