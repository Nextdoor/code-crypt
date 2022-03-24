# Copyright 2017-2022 Nextdoor.com, Inc.
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

from setuptools import find_packages, setup

from code_crypt.metadata import __desc__, __version__

PACKAGE = "code_crypt"
DIR = os.path.dirname(os.path.realpath(__file__))

setup(
    name=PACKAGE,
    version=__version__,
    description=__desc__,
    long_description=open(f"{DIR}/README.md", "rb").read().decode("utf8"),
    author="Nextdoor Engineering",
    author_email="nehal@nextdoor.com",
    url="https://github.com/Nextdoor/code-crypt",
    download_url=f"https://github.com/Nextdoor/code-crypt/tarball/{__version__}",
    license="Apache License, Version 2.0",
    packages=find_packages(),
    tests_require=open(f"{DIR}/requirements.test.txt").readlines(),
    setup_requires=[],
    install_requires=open(f"{DIR}/requirements.txt").readlines(),
    entry_points={"console_scripts": ["code-crypt = code_crypt.cli:main"]},
)
