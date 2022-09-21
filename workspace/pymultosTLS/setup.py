from distutils.core import setup
from distutils.extension import Extension
setup(name='pymultosTLS',
      ext_modules = [Extension('pymultosTLS',
                               libraries = ['multosTLS','multosio','pigpiod_if2','rt'],
                               sources = ['pymultosTLS.c'])])
