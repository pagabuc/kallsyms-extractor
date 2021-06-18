import setuptools

setuptools.setup(
    name='ksymextractor',
    version='0.0.1',
    author='Fabio Pagani',
    author_email='pagani@ucsb.edu',
    description='Tool to extract the kallsyms (System.map) from a memory dump',
    url='https://github.com/pagabuc/kallsyms-extractor',
    packages=['ksymextractor'],
    install_requires=['unicorn'],
    python_requires='>=3.0',
)
