# iputils.py - functions for generating IP strings
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import itertools
# Requires Python 3.3 or greater.
from ipaddress import ip_network
from ipaddress import IPv4Address

#: The default set of prefix lengths for which to generate clues.
DEFAULT_PREFIX_LENGTHS = (8, 16, 24, 32)


def gen_dotted_quad_clues(prefix, address):
    return ('{}:{}'.format(prefix, subnet) for subnet in subnets(address))


def subnets(address, prefix_lengths=None):
    if prefix_lengths is None:
        prefix_lengths = DEFAULT_PREFIX_LENGTHS
    # TODO In Python 3.5, we can use the two-tuple (address, num_bits) argument
    # to `ip_network` in order to avoid converting the prefix length into a
    # string:
    #
    #     net = lambda n: ip_network((address, n), strict=False)
    #
    net = lambda n: ip_network('{}/{}'.format(address, n), strict=False)
    return (net(num_bits) for num_bits in (8, 16, 24, 32))
