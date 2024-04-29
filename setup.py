from setuptools import setup, Extension


setup(
    ext_modules=[
        Extension(
            '_crypt_r',
            sources=[
                'src/_crypt_r.c',
            ],
            libraries=[
                'crypt',
            ],
        )
    ],
)
