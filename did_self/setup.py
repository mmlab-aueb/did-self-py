import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="did-self-py",
    version="0.3",
    author="Nikos Fotiou",
    author_email="fotiou@aueb.gr",
    description="A did:self implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mmlab-aueb/did-self-py",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
)