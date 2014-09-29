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

