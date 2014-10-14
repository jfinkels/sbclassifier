# test_iputils.py - unit tests for the sbclassifier.iputils module
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import ipaddress

from sbclassifier.iputils import gen_dotted_quad_clues


def test_gen_dotted_quad_clues():
    l = list(gen_dotted_quad_clues('foo', '1.23.45.67'))
    assert 'foo:1.0.0.0/8' in l
    assert 'foo:1.23.0.0/16' in l
    assert 'foo:1.23.45.0/24' in l
    assert 'foo:1.23.45.67/32' in l
    l = list(gen_dotted_quad_clues('foo', ipaddress.ip_address('1.23.45.67')))
    assert 'foo:1.0.0.0/8' in l
    assert 'foo:1.23.0.0/16' in l
    assert 'foo:1.23.45.0/24' in l
    assert 'foo:1.23.45.67/32' in l
