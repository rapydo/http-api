# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from rapydo import __version__

setup(
    name='rapydo_http',
    version=__version__,
    author="Paolo D'Onorio De Meo",
    author_email='p.donorio.de.meo@gmail.com',
    url='https://github.com/rapydo/http-api',
    license='MIT',
    # flask_ext & rapydo ?
    packages=find_packages(
        where='.',
        exclude=['test*', 'rapydo.OLD*']
    ),
    package_data={
        'rapydo': ['confs/services.yaml'],
    },
    install_requires=[
        "rapydo-utils",
    ]
)
