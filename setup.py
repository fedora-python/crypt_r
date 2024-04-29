from setuptools import setup, Extension


setup(
    ext_modules=[
        Extension(
            '_crypt',
            sources=[
                'src/_cryptmodule.c',
            ],
            libraries=[
                'crypt',
            ],
        )
    ],
)
