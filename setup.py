from setuptools import setup, find_packages

setup(
    name='bonesi',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'scapy',
        'dpkt',
    ],
    entry_points={
        'console_scripts': [
            'bonesi=src.bonesi:main',
        ],
    },
)
