from distutils.core import setup
from distutils.extension import Extension
setup(name='pymultosTLS',
      ext_modules = [Extension('pymultosTLS',
                               libraries = ['multosio','wiringPi','multosTLS'],
                               sources = ['pymultosTLS.c'])])
