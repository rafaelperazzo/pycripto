import setuptools

setuptools.setup(
    name="python_world",
    version="0.0.1",
    author="Rafael Perazzo",
    packages=setuptools.find_packages(),
    install_requires=['argon2-cffi', 'pycryptodome','python-gnupg'],
    python_requires=">=3.6",
    description="PyCripto",
)