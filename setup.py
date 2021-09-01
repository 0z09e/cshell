import setuptools
from setuptools import setup
setup(
	name='cshell',
	version='1.4',
	url="https://github.com/0z09e/cshell",
	author="Sourav Sen",
	author_email="0z09e.o3@gmail.com",
	description="A command line tool to transfer transfer a webshell into a reverse shell, execute command directly into the webshell, genrating payload",
	long_description=open("README.md").read(),
	long_description_content_type='text/markdown',
	packages=setuptools.find_packages(),
	py_modules=['cshell'],
	install_requires=['requests' , 'pyperclip' , 'IPy' , 'lolcat'],
	entry_points='''
		[console_scripts]
		cshell=cshell:main
	''',
	classifiers=(
		"Programming Language :: Python :: 3",
		"License :: OSI Approved :: GNU General Public License v2 (GPLv2)"
		),

	)