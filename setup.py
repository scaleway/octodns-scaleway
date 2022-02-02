from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_scaleway/__init__.py') as fh:
        for line in fh:
            if line.startswith('__VERSION__'):
                return line.split("'")[1]


description, long_description = descriptions()

setup(
    author='Jeremy JACQUEMIN',
    author_email='domain-team@scaleway.com',
    description=description,
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-scaleway',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=(
        'octodns>=0.9.14',
        'requests>=2.27.0',
    ),
    url='https://github.com/octodns/octodns-scaleway',
    version=version(),
    tests_require=(
        'mock>=4.0.3',
        'pytest',
        'pytest-network',
        'requests_mock'
    ),
)
