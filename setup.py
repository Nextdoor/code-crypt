# Copyright 2017 Nextdoor.com, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from setuptools import setup, find_packages

from code_crypt.metadata import __desc__, __version__

PACKAGE = 'code_crypt'
DIR = os.path.dirname(os.path.realpath(__file__))

setup(
    name=PACKAGE,
    version=__version__,
    description=__desc__,
    long_description=open('%s/README.md' % DIR, 'rb').read().decode('utf8'),
    author='Nextdoor Engineering',
    author_email='nehal@nextdoor.com',
    url='https://github.com/Nextdoor/code-crypt',
    download_url='https://github.com/Nextdoor/code-crypt/tarball/0.1.3',
    license='Apache License, Version 2.0',
    packages=find_packages(),
    test_suite='nose.collector',
    tests_require=open('%s/requirements.test.txt' % DIR).readlines(),
    setup_requires=[],
    install_requires=open('%s/requirements.txt' % DIR).readlines(),
    entry_points={
        'console_scripts': [
            'code-crypt = code_crypt.cli:main']}
)
