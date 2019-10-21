from setuptools import find_packages, setup


with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md") as f:
    readme = f.read()

setup(
    name="kubespec",
    version="0.1.dev20191017",
    url="https://github.com/machinezone/kubespec",
    author="Andy Bursavich",
    author_email="abursavich@mz.com",
    description="Kubespec is a set of foundational libraries for expressing Kubernetes resource specifications as code.",
    long_description=readme,
    long_description_content_type="text/markdown",
    license="BSD 3",
    license_file="LICENSE",
    install_requires=requirements,
    python_requires=">=3.7",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries",
        "Topic :: System",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
)
