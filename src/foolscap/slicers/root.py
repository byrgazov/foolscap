# -*- test-case-name: foolscap.test.test_banana -*-

import types
from functools import reduce

from zope.interface import implementer

from twisted.internet.defer import Deferred
from twisted.python import log

from foolscap import tokens
from foolscap.tokens import Violation, BananaError
from foolscap.slicer import BaseUnslicer, ReferenceSlicer
from foolscap.slicer import UnslicerRegistry, BananaUnslicerRegistry
from foolscap.slicers.vocab import ReplaceVocabularyTable, AddToVocabularyTable
from foolscap import copyable # does this create a cycle?


@implementer(tokens.ISlicer, tokens.IRootSlicer)
class RootSlicer:
    streamableInGeneral = True
    producingDeferred = None
    objectSentDeferred = None
    slicerTable = {}
    debug = False

    def __init__(self, protocol):
        self.protocol  = protocol
        self.sendQueue = []

    def allowStreaming(self, streamable):
        self.streamableInGeneral = streamable

    def registerRefID(self, refid, obj):
        pass

    def slicerForObject(self, obj):
        # could use a table here if you think it'd be faster than an adapter lookup

        if self.debug:
            log.msg('slicerForObject(%s)' % type(obj))

        # do the adapter lookup first, so that registered adapters override
        # UnsafeSlicerTable's InstanceSlicer
        slicer = tokens.ISlicer(obj, None)

        if slicer:
            if self.debug:
                log.msg('got ISlicer %s' % slicer)
            return slicer

        # zope.interface doesn't do transitive adaptation, which is a shame
        # because we want to let people register ICopyable adapters for
        # third-party code, and there is an ICopyable->ISlicer adapter
        # defined in copyable.py, but z.i won't do the transitive
        #  ThirdPartyClass -> ICopyable -> ISlicer
        # so instead we manually do it here

        copier = copyable.ICopyable(obj, None)

        if copier:
            return tokens.ISlicer(copier)

        slicerFactory = self.slicerTable.get(type(obj))

        if slicerFactory:
            if self.debug:
                log.msg(' got slicerFactory %s' % slicerFactory)
            return slicerFactory(obj)

        name = str(type(obj))

        if self.debug:
            log.msg('cannot serialize %s (%s)' % (obj, name))

        raise Violation('cannot serialize %s (%s)' % (obj, name))

    def __iter__(self):
        return self  # we are our own iterator

    def __next__(self):
        if self.objectSentDeferred:
            self.objectSentDeferred.callback(None)
            self.objectSentDeferred = None

        if self.sendQueue:
            (obj, self.objectSentDeferred) = self.sendQueue.pop()
            self.streamable = self.streamableInGeneral
            return obj

        if self.protocol.debugSend:
            print("LAST BAG")

        self.producingDeferred = Deferred()
        self.streamable = True

        return self.producingDeferred

    def slice(self):
        return self

    def next(self):
        return self.__next__()

    def childAborted(self, f):
        assert self.objectSentDeferred
        self.objectSentDeferred.errback(f)
        self.objectSentDeferred = None
        return None

    def send(self, obj):
        # obj can also be a Slicer, say, a CallSlicer. We return a Deferred
        # which fires when the object has been fully serialized.
        idle = (len(self.protocol.slicerStack) == 1) and not self.sendQueue

        objectSentDeferred = Deferred()
        self.sendQueue.append((obj, objectSentDeferred))

        if idle:
            # wake up
            if self.protocol.debugSend:
                print(" waking up to send")

            if self.producingDeferred:
                d = self.producingDeferred
                self.producingDeferred = None
                # TODO: consider reactor.callLater(0, d.callback, None)
                # I'm not sure it's actually necessary, though
                d.callback(None)

        return objectSentDeferred

    def describe(self):
        return "<RootSlicer>"

    def connectionLost(self, why):
        # abandon everything we wanted to send
        if self.objectSentDeferred:
            self.objectSentDeferred.errback(why)
            self.objectSentDeferred = None

        for obj, d in self.sendQueue:
            d.errback(why)

        self.sendQueue = []


class ScopedRootSlicer(RootSlicer):
    # this combines RootSlicer with foolscap.slicer.ScopedSlicer . The funny
    # self-delegation of slicerForObject() means we can't just inherit from
    # both. It would be nice to refactor everything to make this cleaner.

    def __init__(self, obj):
        RootSlicer.__init__(self, obj)
        self.references = {} # maps id(obj) -> (obj,refid)

    def registerRefID(self, refid, obj):
        self.references[id(obj)] = (obj, refid)

    def slicerForObject(self, obj):
        # check for an object which was sent previously or has at least
        # started sending
        obj_refid = self.references.get(id(obj), None)

        if obj_refid is not None:
            # we've started to send this object already, so just include a
            # reference to it
            return ReferenceSlicer(obj_refid[1])

        # otherwise go upstream so we can serialize the object completely
        return super().slicerForObject(obj)


class RootUnslicer(BaseUnslicer):
    # topRegistries is used for top-level objects
    topRegistries = [UnslicerRegistry, BananaUnslicerRegistry]
    # openRegistries is used for everything at lower levels
    openRegistries = [UnslicerRegistry]
    constraint = None
    openCount = None

    def __init__(self, protocol):
        self.protocol = protocol
        self.objects = {}
        keys = []
        for r in self.topRegistries + self.openRegistries:
            for k in r.keys():
                keys.append(len(k[0]))
        self.maxIndexLength = reduce(max, keys)

    def start(self, count):
        pass

    def setConstraint(self, constraint):
        # this constraints top-level objects. E.g., if this is an
        # IntegerConstraint, then only integers will be accepted.
        self.constraint = constraint

    def checkToken(self, typebyte, size):
        if self.constraint:
            self.constraint.checkToken(typebyte, size)

    def openerCheckToken(self, typebyte, size, opentype):
        if opentype == (b'copyable',) and typebyte in (tokens.STRING, tokens.SVOCAB):
            # TODO: this is silly, of course (should pre-compute maxlen)
            maxlen = reduce(max, map(len, copyable.CopyableRegistry.keys()))
            if maxlen < size:
                raise Violation('copyable-classname token is too long, {:d} > {:d}'\
                    .format(size, maxlen))

        elif typebyte == tokens.BYTES:
            if self.maxIndexLength < size:
                raise Violation('first opentype BYTES token is too long, {:d} > {:d}'\
                    .format(size, self.maxIndexLength))

        elif typebyte != tokens.BVOCAB:
            raise Violation('opentype not <copyable> ({!r}) and index token 0x{:02x} not BYTES or BVOCAB'\
                .format(opentype, ord(typebyte)))

    def open(self, opentype):
        # called (by delegation) by the top Unslicer on the stack, regardless
        # of what kind of unslicer it is. This is only used for "internal"
        # objects: non-top-level nodes
        assert len(self.protocol.receiveStack) > 1

        if opentype[0] == b'copyable':
            if len(opentype) > 1:
                copyablename = opentype[1]
                try:
                    factory = copyable.CopyableRegistry[copyablename]
                except KeyError:
                    raise Violation("unknown RemoteCopy name '%s'" % copyablename)

                return factory()

            # still waiting for copyablename

        else:
            for reg in self.openRegistries:
                opener = reg.get(opentype)
                if opener is not None:
                    return opener()

            raise Violation("unknown OPEN type %s" % (opentype,))

    def doOpen(self, opentype):
        # this is only called for top-level objects
        assert len(self.protocol.receiveStack) == 1

        if self.constraint:
            self.constraint.checkOpentype(opentype)

        for reg in self.topRegistries:
            opener = reg.get(opentype)
            if opener is not None:
                child = opener()
                break
        else:
            raise Violation("unknown top-level OPEN type %s" % (opentype,))

        if self.constraint:
            child.setConstraint(self.constraint)

        return child

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None

        if self.protocol.debugReceive:
            print("RootUnslicer.receiveChild(%s)" % (obj,))

        self.objects = {}

        if obj in (ReplaceVocabularyTable, AddToVocabularyTable):
            pass  # the unslicer has already changed the vocab table
        elif self.protocol.exploded:
            print("protocol exploded, can't deliver object")
            print(self.protocol.exploded)
            self.protocol.receivedObject(self.protocol.exploded)
        else:
            self.protocol.receivedObject(obj) # give finished object to Banana

    def receiveClose(self):
        raise BananaError("top-level should never receive CLOSE tokens")

    def reportViolation(self, why):
        return self.protocol.reportViolation(why)

    def describe(self):
        return "<RootUnslicer>"

    def setObject(self, counter, obj):
        pass

    def getObject(self, counter):
        pass


class ScopedRootUnslicer(RootUnslicer):
    # combines RootUnslicer and ScopedUnslicer

    def __init__(self, protocol):
        RootUnslicer.__init__(self, protocol)
        self.references = {}

    def setObject(self, counter, obj):
        self.references[counter] = obj

    def getObject(self, counter):
        obj = self.references.get(counter)
        return obj
