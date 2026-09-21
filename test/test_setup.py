import sys

import gmpy2


def test_python_version():
    assert sys.version_info[:2] == (3, 12)


def test_gmpy2_available():
    assert gmpy2.version()