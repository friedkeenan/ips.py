import setuptools

with open("README.md") as f:
    long_description = f.read()

setuptools.setup(
    name="ips.py",
    version="0.1.0",
    author="friedkeenan",
    description="A Python library for handling IPS patches",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/friedkeenan/ips.py",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)