from setuptools import setup, find_packages

setup(
       name='CryptoTools',
       version='0.1',
       packages=find_packages(),
       install_requires=[
           'cryptography',
       ],
       description='A simple package for encryption and decryption',
       author='Ваше имя',
       author_email='ipatova.evgenija@mail.ru',
       url='https://github.com/JoeDavisRAM/CryptoTools',
   )