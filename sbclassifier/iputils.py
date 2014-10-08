# iputils.py - functions for generating IP strings
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
def gen_dotted_quad_clues(pfx, ips):
    for ip in ips:
        yield "%s:%s/32" % (pfx, ip)
        dottedQuadList = ip.split(".")
        yield "%s:%s/8" % (pfx, dottedQuadList[0])
        yield "%s:%s.%s/16" % (pfx, dottedQuadList[0],
                               dottedQuadList[1])
        yield "%s:%s.%s.%s/24" % (pfx, dottedQuadList[0],
                                  dottedQuadList[1],
                                  dottedQuadList[2])

