from setuptools import setup, Extension


setup(
    ext_modules=[
        Extension(
            '_crypt',
            sources=[
                'Modules/_cryptmodule.c',
            ],
            libraries=[
                'crypt',
            ],
        )
    ],
)
