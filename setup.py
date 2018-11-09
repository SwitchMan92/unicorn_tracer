#!/usr/bin/env python

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
                name='unicorn_tracer',
                version='1.1.1',
                description='memory modifications tracing tool for the unicorn cpu emulator',
                author='Tom Langfeldt',
                url='https://github.com/SwitchMan92/unicorn_tracer',
                packages=setuptools.find_packages(),
                install_requires=['termcolor', 'unicorn'],
                python_requires='==2.*',
                classifiers=[
                    "Programming Language :: Python :: 2.7",
                    "License :: OSI Approved :: GNU General Public License (GPL)",
                    "Operating System :: OS Independent",
                  ],
                package_data={
                    '': ['*.txt', '*.rst', '*.bin', 'LICENSE', '*.md']
                }
      )
