import setuptools

desc_file = "README.md"

with open(desc_file, "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="casbin",
    version="0.5",
    author="TechLee",
    author_email="techlee@qq.com",
    description="An authorization library that supports access control models like ACL, RBAC, ABAC in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/casbin/pycasbin",
    keywords=["casbin", "rbac", "access control", "abac", "acl", "permission"],
    packages=setuptools.find_packages(),
    install_requires=['simpleeval>=0.9.8'],
    python_requires=">=3.3",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    data_files=[desc_file],
)
