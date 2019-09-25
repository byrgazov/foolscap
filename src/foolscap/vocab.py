
import hashlib

# here is the list of initial vocab tables. If the two ends negotiate to use
# initial-vocab-table-index N, then both sides will start with the words from
# INITIAL_VOCAB_TABLES[n] for their VOCABized tokens.

vocab_v0 = []
vocab_v1 = [ # all opentypes used in 0.0.6
    b'none', b'boolean', b'reference',
    b'dict', b'list', b'tuple', b'set', b'immutable-set',
    b'unicode', b'set-vocab', b'add-vocab',
    b'call', b'arguments', b'answer', b'error',
    b'my-reference', b'your-reference', b'their-reference', b'copyable',
    # these are only used by storage.py
    b'instance', b'module', b'class', b'method', b'function',
    # I'm not sure this one is actually used anywhere, but the first 127 of these are basically free.
    b'attrdict',
]

vocab_v191 = vocab_v1[:]
#       b'unpersistable': --,
#       b'copy'         : 13,
#       b'cache'        : 14,
#       b'cached'       : 15,
#       b'remote'       : 16,
#       b'local'        : 17,
#       b'lcache'       : 18,
#       b'version'      : 19,
#       b'login'        : 20,
#       b'password'     : 21,
#       b'challenge'    : 22,
#       b'logged_in'    : 23,
#       b'not_logged_in': 24,
#       b'cachemessage' : 25,
#       b'message'      : 26,
#       b'answer'       : 27,
#       b'error'        : 28,
#       b'decref'       : 29,
#       b'decache'      : 30,
#       b'uncache'      : 31,

vocab_v191 += [
    b'slice',
    b'exception',
    b'uuid',
    b'datetime',
    b'timedelta',
    b'time',
    b'date',
    b'decimal'
]

assert len(vocab_v191) < 127, len(vocab_v191)

INITIAL_VOCAB_TABLES = {0: vocab_v0, 1: vocab_v1, 191: vocab_v191}


# to insure both sides agree on the actual words, we can hash the vocab table
# into a short string. This is included in the negotiation decision and
# compared by the receiving side.


def hashVocabTable(table_index):
    data = b'\x00'.join(INITIAL_VOCAB_TABLES[table_index])
    digest = hashlib.sha1(data).hexdigest()
    return digest[:8]


def getVocabIndices():
    return sorted(INITIAL_VOCAB_TABLES.keys())
