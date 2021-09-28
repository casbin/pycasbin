import setuptools
from os import path

desc_file = "README.md"

here = path.abspath(path.dirname(__file__))

with open(desc_file, "r", encoding="utf-8") as fh:
    long_description = fh.read()

# get the dependencies and installs
with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    all_reqs = f.read().split("\n")

install_requires = [x.strip() for x in all_reqs if "git+" not in x]

setuptools.setup(
    name="casbin",
    author="TechLee",
    author_email="techlee@qq.com",
    description="An authorization library that supports access control models like ACL, RBAC, ABAC in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/casbin/pycasbin",
    keywords=[
        "casbin",
        "acl",
        "rbac",
        "abac",
        "auth",
        "authz",
        "authorization",
        "access control",
        "permission",
    ],
    packages=setuptools.find_packages(exclude=("tests",)),
    install_requires=install_requires,
    python_requires=">=3.3",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    data_files=[desc_file],
)
