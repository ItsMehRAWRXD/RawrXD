#!/usr/bin/env python3
"""Setup script for OMEGA-1 Engine Python bindings"""

from setuptools import setup, find_packages
import os

# Read README
readme_path = os.path.join(os.path.dirname(__file__), '..', '..', 'OMEGA1_CMAKE_INTEGRATION.md')
long_description = ""
try:
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()
except:
    long_description = "OMEGA-1 Engine Python bindings"

setup(
    name='rawrxd-omega1',
    version='1.0.0',
    author='RawrXD Team',
    author_email='team@rawrxd.dev',
    description='OMEGA-1 Self-Mutating Engine Python bindings',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/ItsMehRAWRXD/rawrxd',
    py_modules=['omega1_engine'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    python_requires='>=3.8',
    install_requires=[
        # No external dependencies - uses ctypes only
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov>=4.0',
            'black>=23.0',
            'mypy>=1.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'omega1=omega1_engine:main',
        ],
    },
    keywords='rawrxd omega1 powershell native ffi',
    project_urls={
        'Bug Reports': 'https://github.com/ItsMehRAWRXD/rawrxd/issues',
        'Source': 'https://github.com/ItsMehRAWRXD/rawrxd',
    },
)
