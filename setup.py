from setuptools import setup, find_packages

# Read the requirements from the requirements.txt file
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="Predator",
    version="1.1.0",
    description="Predator.",
    author="Anonyxbiz",
    author_email="anonyxbiz@gmail.com",
    url="https://github.com/anonyxbiz/Predator",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    py_modules=['Predator'],
    python_requires='>=3.6',
)
