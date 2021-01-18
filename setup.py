import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="token_authenticator", # Replace with your own username
    version="0.1.0",
    author="Sorunome",
    author_email="mail@sorunome.de",
    description="A jwt based token authenticator for synapse",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/famedly/synapse-token-authenticator",
    packages=setuptools.find_packages(),
    install_requires=[
        "jwcrypto",
        "twisted",
    ],
    tests_require=[
        "mock",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
    ],
    python_requires='>=3.6',
)
