#!/usr/bin/env python

import io
import os

from setuptools import setup

# Use README.md to set markdown long_description
directory = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(directory, "README.md")
with io.open(readme_path, encoding="utf-8") as read_file:
    long_description = read_file.read()

setup(name="importaddress",
      version="1.1",
      description="Bitcoin addresses generator by using HD protocol",
      long_description=long_description,
      long_description_content_type='text/markdown',
      author="kcorlidy Chan",
      author_email="kcorlidy@outlook.com",
      url="https://github.com/kcorlidy/importaddress",
      packages=["importaddress"],
      package_data={"importaddress": ["data/*.md"]},
      license="Apache",
      python_requires=">2.6, >3.3",
      classifiers=[
          "Programming Language :: Python",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
      ],
      install_requires=["mnemonic",
                        "ecdsa"],
      )
