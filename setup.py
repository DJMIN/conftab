#!/usr/bin/env python
# coding=utf-8

from setuptools import setup, find_packages
from version import __VERSION__
setup(
    name='conftab',
    version=__VERSION__,
    description=(
        'config version manager with web or code easily'
    ),
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author='readerror',
    author_email='readerror@sina.com',
    maintainer='readerror',
    maintainer_email='readerror@sina.com',
    license='GPL License',
    packages=find_packages(),
    platforms=["all"],
    url='https://github.com/DJMIN/conftab',
    python_requires='>=3.7',
    install_requires=[
       "fastapi",
       "requests",
       "uvicorn",
       "click",
       "sqlalchemy",
       "python-multipart",
       "wheel",
       "twine",
    ],
)