from sbclassifier.cdb import cdb_make
from sbclassifier.cdb import Cdb

def test():
    #db = Cdb(open("t"))
    #print db['one']
    #print db['two']
    #print db['foo']
    #print db['us']
    #print db.get('ec')
    #print db.get('notthere')
    db = open('test.cdb', 'wb')
    cdb_make(db,
             [('one', 'Hello'),
              ('two', 'Goodbye'),
              ('foo', 'Bar'),
              ('us', 'United States'),
              ])
    db.close()
    db = Cdb(open("test.cdb", 'rb'))
    print(db['one'])
    print(db['two'])
    print(db['foo'])
    print(db['us'])
    print(db.get('ec'))
    print(db.get('notthere'))
