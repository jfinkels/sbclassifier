# cdb.py - Python implementation of cdb
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
"""
Dan Bernstein's CDB implemented in Python

see http://cr.yp.to/cdb.html

"""
import os
import struct
import mmap


def uint32_unpack(buf):
    return struct.unpack('<L', buf)[0]


def uint32_pack(n):
    return struct.pack('<L', n)

CDB_HASHSTART = 5381


def cdb_hash(buf):
    h = CDB_HASHSTART
    for c in buf:
        h = (h + (h << 5)) & 0xffffffff
        h ^= ord(c)
    return h


class Cdb(object):

    def __init__(self, fp):
        self.fp = fp
        fd = fp.fileno()
        self.size = os.fstat(fd).st_size
        self.map = mmap.mmap(fd, self.size, access=mmap.ACCESS_READ)
        self.eod = uint32_unpack(self.map[:4])
        self.findstart()
        self.loop = 0  # number of hash slots searched under this key
        # initialized if loop is nonzero
        self.khash = 0
        self.hpos = 0
        self.hslots = 0
        # initialized if findnext() returns 1
        self.dpos = 0
        self.dlen = 0

    def close(self):
        self.map.close()

    def __iter__(self, fn=None):
        len = 2048
        while len < self.eod:
            klen, vlen = struct.unpack("<LL", self.map[len:len+8])
            len += 8
            key = self.map[len:len+klen]
            len += klen
            val = self.map[len:len+vlen]
            len += vlen
            if fn:
                yield fn(key, val)
            else:
                yield (key, val)

    def iteritems(self):
        return self.__iter__()

    def iterkeys(self):
        return self.__iter__(lambda k, v: k)

    def itervalues(self):
        return self.__iter__(lambda k, v: v)

    def items(self):
        ret = []
        for i in self.iteritems():
            ret.append(i)
        return ret

    def keys(self):
        ret = []
        for i in self.iterkeys():
            ret.append(i)
        return ret

    def values(self):
        ret = []
        for i in self.itervalues():
            ret.append(i)
        return ret

    def findstart(self):
        self.loop = 0

    def read(self, n, pos):
        # XXX add code for platforms without mmap
        return self.map[pos:pos+n]

    def match(self, key, pos):
        if key == self.read(len(key), pos):
            return 1
        else:
            return 0

    def findnext(self, key):
        if not self.loop:
            u = cdb_hash(key)
            buf = self.read(8, u << 3 & 2047)
            self.hslots = uint32_unpack(buf[4:])
            if not self.hslots:
                raise KeyError
            self.hpos = uint32_unpack(buf[:4])
            self.khash = u
            u >>= 8
            u %= self.hslots
            u <<= 3
            self.kpos = self.hpos + u

        while self.loop < self.hslots:
            buf = self.read(8, self.kpos)
            pos = uint32_unpack(buf[4:])
            if not pos:
                raise KeyError
            self.loop += 1
            self.kpos += 8
            if self.kpos == self.hpos + (self.hslots << 3):
                self.kpos = self.hpos
            u = uint32_unpack(buf[:4])
            if u == self.khash:
                buf = self.read(8, pos)
                u = uint32_unpack(buf[:4])
                if u == len(key):
                    if self.match(key, pos + 8):
                        dlen = uint32_unpack(buf[4:])
                        dpos = pos + 8 + len(key)
                        return self.read(dlen, dpos)
        raise KeyError

    def __getitem__(self, key):
        self.findstart()
        return self.findnext(key)

    def get(self, key, default=None):
        self.findstart()
        try:
            return self.findnext(key)
        except KeyError:
            return default


# def cdb_dump(infile):
#     """dump a database in djb's cdbdump format"""
#     db = Cdb(infile)
#     for key, value in db.iteritems():
#         print "+%d,%d:%s->%s" % (len(key), len(value), key, value)
#     print


def cdb_make(outfile, items):
    pos = 2048
    tables = {}  # { h & 255 : [(h, p)] }

    # write keys and data
    outfile.seek(pos)
    for key, value in items:
        outfile.write(uint32_pack(len(key)) + uint32_pack(len(value)))
        h = cdb_hash(key)
        outfile.write(bytes(key, 'utf-8'))
        outfile.write(bytes(value, 'utf-8'))
        tables.setdefault(h & 255, []).append((h, pos))
        pos += 8 + len(key) + len(value)

    final = bytes('', 'utf-8')
    # write hash tables
    for i in range(256):
        entries = tables.get(i, [])
        nslots = 2*len(entries)
        final += uint32_pack(pos) + uint32_pack(nslots)
        null = (0, 0)
        table = [null] * nslots
        for h, p in entries:
            n = (h >> 8) % nslots
            while table[n] is not null:
                n = (n + 1) % nslots
            table[n] = (h, p)
        for h, p in table:
            outfile.write(uint32_pack(h) + uint32_pack(p))
            pos += 8

    # write header (pointers to tables and their lengths)
    outfile.flush()
    outfile.seek(0)
    outfile.write(final)
