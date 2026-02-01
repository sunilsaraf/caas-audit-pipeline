from setuptools import setup, find_packages

setup(
    name="caas-audit-pipeline",
    version="0.1.0",
    description="Compliance-as-a-Service for Object Storage Using Cryptographically Verifiable Audit Pipelines",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography>=41.0.0",
        "pydantic>=2.0.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
        ]
    },
    python_requires=">=3.8",
)
