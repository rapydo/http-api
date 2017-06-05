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
        # FIXME: choose the right list here
        # p.s. also consider models/swagger.yaml and swagger/*
        'rapydo': ['confs/services.yaml'],
    },
    install_requires=[
        # TODO: complete this list
        # from requirements in builds/backend/requirements.txt
        "attrs",
        "better_exceptions",
        "Flask",
        "flask_injector==v0.9.0",
        "injector==0.12.0",
        "bravado-core",
        "rapydo-utils",
    ]
)
