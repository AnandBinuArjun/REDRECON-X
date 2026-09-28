import os
from setuptools import setup, find_packages

setup(
    name="redrecon-x",
    version="1.0.0",
    author="REDRECON-X Authors",
    description="Automated Web Reconnaissance & Attack-Surface Intelligence Framework",
    long_description=open("README.md", encoding="utf-8").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "pydantic>=2.5.0",
        "httpx>=0.25.0",
        "dnspython>=2.4.0",
        "beautifulsoup4>=4.12.0",
        "pyyaml>=6.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "redrecon=redrecon.cli.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
