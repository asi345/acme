from setuptools import setup

setup(
    name="acme-project",
    version="0.1",
    description="ACME Client lib",
    author="Tom Cinbis",
    license="MIT",
    packages=["src"],
    zip_safe=False,
    install_requires=[
        "Flask==1.1.2",
        "cryptography==3.1",
        "dnslib==0.9.14",
        "requests==2.24.0",
        "pycryptodome==3.9.8",
        "dacite==1.5.1",
    ],
)
