from setuptools import setup, find_packages

setup(
    name='libcst',
    version='1.8.0', 
    packages=find_packages(),
    install_requires=[
        'apscheduler',
        'asyncio',
        'pymongo',
        'cryptography',
    ],
    author='Elliot Harper',
    author_email='elliot.harper@libcst.org',
    description='A lightweight Python library for efficient resource management and modular utilities.',
)
