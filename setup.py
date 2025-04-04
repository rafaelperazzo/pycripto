'''
Referência: https://github.com/ceddlyburge/python_world/blob/master/README.md
'''
import setuptools

setuptools.setup(
    name="cripto",
    version="1.0.0",
    author="Rafael Perazzo",
    packages=setuptools.find_packages(),
    install_requires=['argon2-cffi', 'pycryptodome','python-gnupg'],
    python_requires=">=3.6",
    description="PyCripto",
)