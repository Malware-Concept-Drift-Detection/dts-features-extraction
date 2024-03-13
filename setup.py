from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="ml-malware-concept-drift",
    version="0.1.0",
    description="ML-driven malware classification and Concept drift detection",
    url="#",
    author="Luca Fabri",
    author_email="luca.fabri1999@gmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    # setup_requires=["pytest-runner"],
    # tests_require=["pytest"],
    # test_suite="src.test",
    install_requires=requirements,
    zip_safe=False,
    python_requires="==3.11.6",
)
