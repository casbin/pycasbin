import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="casbin",
    version="0.1.1",
    author="TechLee",
    author_email="techlee@qq.com",
    description="An authorization library that supports access control models like ACL, RBAC, ABAC in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/casbin/pycasbin",
    keywords=["casbin", "rbac", "access control", "abac", "acl", "permission"],
    packages=setuptools.find_packages(),
    install_requires=['simpleeval>=0.9.8'],
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
