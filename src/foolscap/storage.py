
"""
storage.py: support for using Banana as if it were pickle

This includes functions for serializing to and from strings, instead of a
network socket. It also has support for serializing 'unsafe' objects,
specifically classes, modules, functions, and instances of arbitrary classes.
These are 'unsafe' because to recreate the object on the deserializing end,
we must be willing to execute code of the sender's choosing (i.e. the
constructor of whatever package.module.class names they send us). It is
unwise to do this unless you are willing to allow your internal state to be
compromised by the author of the serialized data you're unpacking.

This functionality is isolated here because it is never used for data coming
over network connections.
"""

import sys
import io
import types
import inspect
import operator as O

import pickle
from pickle import whichmodule  # used by FunctionSlicer

from twisted.internet.defer import Deferred
from twisted.python import reflect

from foolscap import slicer, banana, tokens
from foolscap.slicer       import BaseSlicer
from foolscap.slicers.root import ScopedRootSlicer, ScopedRootUnslicer

from .tokens import BananaError, Violation


#ClassType   = getattr(types, 'ClassType',    type)
InstanceType = getattr(types, 'InstanceType', object)


UnsafeUnslicerRegistry = {}


################## Slicers for "unsafe" things

# Extended types, not generally safe. The UnsafeRootSlicer checks for these
# with a separate table.

class InstanceSlicer(BaseSlicer):
    opentype = (b'instance',)
    trackReferences = True

    pickle_protocol = pickle.DEFAULT_PROTOCOL
    ordered_state = False  # @note: использую для тестов

    def __init__(self, obj):
        assert not issubclass(type(obj), type), (type(obj), obj)  # @see: pickle
#       if issubclass(type(obj), type):
#           raise Violation('Instance expected', type(obj), obj)
        super().__init__(obj)

    def sliceBody(self, streamable, banana):
        # @see: Pickle.save

        type_obj = type(self.obj)

        reduce = getattr(self.obj, '__reduce_ex__', None)

        if reduce is not None:
            try:
                rv = reduce(self.pickle_protocol)
            except TypeError as exc:
                raise Violation(str(exc))
        else:
            reduce = getattr(self.obj, '__reduce__', None)
            if reduce is None:
                raise BananaError('Can\'t pickle {!r} object: {!r}'.format(type_obj, self.obj))
            rv = reduce()

        if isinstance(rv, str):
            raise NotImplementedError(self.obj, rv)

        if not isinstance(rv, tuple):
            raise BananaError('{!r} must return string or tuple'.format(reduce))

        rv_len = len(rv)

        if rv_len < 2 or 5 < rv_len:
            raise BananaError('Tuple {!r} returned by {!r} must have two to five elements'\
                .format(rv, reduce))

#       def unpack_rv(func, args, state=None, listitems=None, dictitems=None):
#           return func, args, state, listitems, dictitems
#       func, args, state, listitems, dictitems = unpack_rv()

        # @see: Pickle.save_reduce

        func, args, *rv_rest = rv
        state, listitems, dictitems = tuple(rv_rest) + (None,) * (5 - rv_len)

        assert state is None or type(state) is dict, (type(state), state)

        if listitems is not None:
            raise NotImplementedError('listitems', self.obj, rv)

        if dictitems is not None:
            raise NotImplementedError('dictitems', self.obj, rv)

        func_name = getattr(func, '__name__', '')

        if 4 <= self.pickle_protocol and func_name == '__newobj_ex__':
            cls, args, kwargs = args

            if not hasattr(cls, '__new__'):
                raise BananaError('args[0] from __newobj_ex__ args has no __new__', cls, args)

            if cls is not type_obj:
                raise BananaError('args[0] from __newobj_ex__ args has the wrong class', cls, args)

            yield 4
            yield cls
            yield tuple(args)
            yield kwargs
            # NEWOBJ_EX

        elif 2 <= self.pickle_protocol and func_name == '__newobj__':
            cls, *args = args

            if not hasattr(cls, '__new__'):
                raise BananaError('args[0] from __newobj__ args has no __new__', cls, args)

            if cls is not type_obj:
                raise BananaError('args[0] from __newobj__ args has the wrong class', cls, args)

            yield 2
            yield cls
            yield tuple(args)
            # NEWOBJ

        else:
            yield 0
            yield func
            yield args
            # REDUCE

        if state:
            if self.ordered_state:
                state_items = sorted(state.items(), key=O.itemgetter(0))
            else:
                state_items = state.items()

            for key, value in state_items:
                yield key
                yield value

            # BUILD

        # @todo: listitems & dictitems

    def describe(self):
        return '<instance of {}>'.format(type(self.obj).__name__)


class InstanceUnslicer(slicer.BaseUnslicer):
    # this is an unsafe unslicer: an attacker could induce you to create
    # instances of arbitrary classes with arbitrary attributes: VERY
    # DANGEROUS!

    opentype  = (b'instance',)
    unslicerRegistry = UnsafeUnslicerRegistry

    pickle_protocol = None
    reduce_func = None
    reduce_args = None
    new_cls    = None
    new_args   = None
    new_kwargs = None
    state      = None
    state_key  = None
    listitems  = None  # @xxx: not implemented
    dictitems  = None  # @xxx: not implemented

    num_unreferenceable_children         = 0
    all_children_are_referenceable_defer = None

    # danger: instances are mutable containers. If an attribute value is not
    # yet available, __dict__ will hold a Deferred until it is. Other
    # objects might be created and use our object before this is fixed.
    # TODO: address this. Note that InstanceUnslicers aren't used in PB
    # (where we have pb.Referenceable and pb.Copyable which have schema
    # constraints and could have different restrictions like not being
    # allowed to participate in reference loops).

    def start(self, count):
        self.count = count
        self.deferred = Deferred()
        self.protocol.setObject(count, self.deferred)

    def checkToken(self, typebyte, size):
        if self.pickle_protocol is None:
            if typebyte != tokens.INT:
                raise BananaError('InstanceUnslicer `pickle_protocol` token must be INT, got 0x{:x}'.format(ord(typebyte)))

        elif self.pickle_protocol == 4:
            # @todo: more tests

            if self.new_cls is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `new_cls` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.new_args is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `new_args` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.new_kwargs is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `new_kwargs` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.state_key is None:
                if typebyte not in (tokens.STRING, tokens.SVOCAB):
                    raise BananaError('InstanceUnslicer `state_key` token must be STRING or SVOCAB, got 0x{:x}'.format(ord(typebyte)))

        elif self.pickle_protocol == 2:
            # @todo: more tests

            if self.new_cls is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `new_cls` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.new_args is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `new_args` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.state_key is None:
                if typebyte not in (tokens.STRING, tokens.SVOCAB):
                    raise BananaError('InstanceUnslicer `state_key` token must be STRING or SVOCAB, got 0x{:x}'.format(ord(typebyte)))

        elif self.pickle_protocol == 0:
            # @todo: more tests

            if self.reduce_func is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `reduce_func` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.reduce_args is None:
                if typebyte != tokens.OPEN:
                    raise BananaError('InstanceUnslicer `reduce_args` token must be OPEN, got 0x{:x}'.format(ord(typebyte)))
            elif self.state_key is None:
                if typebyte not in (tokens.STRING, tokens.SVOCAB):
                    raise BananaError('InstanceUnslicer `state_key` token must be STRING or SVOCAB, got 0x{:x}'.format(ord(typebyte)))

        else:
            raise BananaError('Unknown `pickle_protocol`', self.pickle_protocol)

    def receiveChild(self, obj, ready_deferred=None):
        assert ready_deferred is None

        # @todo: (?) finite state machine

#       print('--receiveChild--', self, obj)

        if self.state is None:
            if isinstance(obj, Deferred):
                raise NotImplementedError

            if self.pickle_protocol is None:
                self.pickle_protocol = obj

            elif self.pickle_protocol == 4:
                if   self.new_cls    is None: self.new_cls    = obj
                elif self.new_args   is None: self.new_args   = obj
                elif self.new_kwargs is None: self.new_kwargs = obj
                elif self.state      is None: self.state      = {}
                else: raise BananaError('Unexpected child', obj)

            elif self.pickle_protocol == 2:
                if   self.new_cls  is None: self.new_cls  = obj
                elif self.new_args is None: self.new_args = obj
                elif self.state    is None: self.state    = {}
                else: raise BananaError('Unexpected child', obj)

            elif self.pickle_protocol == 0:
                if   self.reduce_func is None: self.reduce_func = obj
                elif self.reduce_args is None: self.reduce_args = obj
                elif self.state       is None: self.state       = {}
                else: raise BananaError('Unexpected child', obj)

            else:
                raise BananaError('Unknown `pickle_protocol`', self.pickle_protocol)

        if self.state is not None:
            if self.state_key is None:
                if isinstance(obj, Deferred):
                    raise NotImplementedError

                if obj in self.state:
                    raise BananaError('Duplicate attribute name "{}"'.format(obj))

                self.state_key = obj

            else:
                if isinstance(obj, Deferred):
                    def setstate(value, key):
                        self.state[key] = value

                        self.num_unreferenceable_children -= 1

                        if not self.num_unreferenceable_children and self.all_children_are_referenceable_defer:
                            self.all_children_are_referenceable_defer.callback(None)

                    self.num_unreferenceable_children += 1

                    obj.addCallback(setstate, self.state_key)

                else:
                    self.state[self.state_key] = obj

                del self.state_key

    def receiveClose(self):
        # you could attempt to do some value-checking here, but there would
        # probably still be holes

        if self.pickle_protocol == 4:
            obj = self.new_cls.__new__(self.new_cls, *self.new_args, **self.new_kwargs)

        elif self.pickle_protocol == 2:
            obj = self.new_cls.__new__(self.new_cls, *self.new_args)

        elif self.pickle_protocol == 0:
            obj = self.reduce_func(*self.reduce_args)

        else:
            raise BananaError('Unknown `pickle_protocol`', self.pickle_protocol)

#       print('--receiveClose--', self, obj)

        def setstate():
            setstate = getattr(obj, '__setstate__', None)

            if setstate is not None:
                setstate(self.state)

            else:
                # @todo: state is tuple = slotstate

                #slotstate = None
                #if isinstance(state, tuple) and len(state) == 2:
                #    state, slotstate = state
                #if state:

                obj_dict = obj.__dict__

                intern = sys.intern

                for key, value in self.state.items():
                    if type(key) is str:
                        obj_dict[intern(key)] = value
                    else:
                        obj_dict[key] = value

                #if slotstate:
                #    for key, value in slotstate.items():
                #        setattr(obj, key, value)

#           print('--receiveClose-setstate--', self, vars(obj))

        if self.num_unreferenceable_children:
            # @xxx: мне всё это не нравится
            self.all_children_are_referenceable_defer = Deferred()
            self.all_children_are_referenceable_defer.addCallback(lambda _: setstate())
            # @todo: (?) addErrback

        elif self.state:
            setstate()

        self.protocol.setObject(self.count, obj)
        self.deferred.callback(obj)

        return obj, None

    def describe(self):
        if self.reduce_args:
            cls = self.reduce_args[0]
        elif self.new_cls:
            cls = self.new_cls
        else:
            return '<instance>'
        return '<instance of {}>'.format(cls.__name__)


class ModuleSlicer(slicer.BaseSlicer):
    opentype = (b'module',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        yield self.obj.__name__


class ClassSlicer(slicer.BaseSlicer):
    opentype = (b'class',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        yield reflect.qual(self.obj)


class MethodSlicer(slicer.BaseSlicer):
    opentype = (b'method',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        if self.obj.__self__ is None:
            yield self.obj.__func__.__qualname__
        else:
            yield self.obj.__func__.__name__
        yield self.obj.__self__
#       yield self.obj.__class__


class FunctionSlicer(slicer.BaseSlicer):
    opentype = (b'function',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
#       name = self.obj.__name__
#       fullname = str(whichmodule(self.obj, self.obj.__name__)) + '.' + name
        fullname = self.obj.__module__ + '.' + self.obj.__qualname__
        yield fullname


UnsafeSlicerTable = {
    types.ModuleType: ModuleSlicer,
#   InstanceType: InstanceSlicer,
#   ClassType   : ClassSlicer,
    InstanceType: None,
    type        : ClassSlicer,
    types.MethodType  : MethodSlicer,
    types.FunctionType: FunctionSlicer,
    #types.TypeType: NewstyleClassSlicer,
    # ???: NewstyleInstanceSlicer,  # pickle uses obj.__reduce__ to help
    # http://docs.python.org/lib/node68.html
}


# the root slicer for storage is exactly like the regular root slicer
class StorageRootSlicer(ScopedRootSlicer):
    pass


# but the "unsafe" one (which handles instances and stuff) uses its own table
class UnsafeStorageRootSlicer(StorageRootSlicer):
    slicerTable = UnsafeSlicerTable

    def slicerForObject(self, obj):
        try:
            slicer = super().slicerForObject(obj)
        except Violation:
            # @xxx: InstanceType
            if InstanceType not in self.slicerTable:
                raise
#           if not inspect.isclass(type(obj)):
            if issubclass(type(obj), type):
                raise
            slicer = InstanceSlicer(obj)
        return slicer


################## Unslicers for "unsafe" things


class Dummy:
    def __repr__(self):
        return '<Dummy %s>' % self.__dict__

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __lt__(self, other):
        if type(other) is type(self):
            return self.__dict__ < other.__dict__
        return NotImplemented


class ModuleUnslicer(slicer.LeafUnslicer):
    opentype = (b'module',)
    unslicerRegistry = UnsafeUnslicerRegistry

    finished = False

    def checkToken(self, typebyte, size):
        if typebyte not in (tokens.STRING, tokens.SVOCAB):
            raise BananaError("ModuleUnslicer only accepts STRINGs")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.finished:
            raise BananaError("ModuleUnslicer only accepts one string")
        self.finished = True
        # TODO: taste here!
        mod = __import__(obj, {}, {}, "x")
        self.mod = mod

    def receiveClose(self):
        if not self.finished:
            raise BananaError("ModuleUnslicer requires a string")
        return self.mod, None


class ClassUnslicer(slicer.LeafUnslicer):
    opentype = (b'class',)
    unslicerRegistry = UnsafeUnslicerRegistry

    finished = False

    def checkToken(self, typebyte, size):
        if typebyte not in (tokens.STRING, tokens.SVOCAB):
            raise BananaError("ClassUnslicer only accepts STRINGs")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.finished:
            raise BananaError("ClassUnslicer only accepts one string")
        self.finished = True
        # TODO: taste here!
        self.klass = reflect.namedObject(obj)

    def receiveClose(self):
        if not self.finished:
            raise BananaError("ClassUnslicer requires a string")
        return self.klass, None


class MethodUnslicer(slicer.BaseUnslicer):
    opentype = (b'method',)
    unslicerRegistry = UnsafeUnslicerRegistry

    state = 0
    im_func = None
    im_self = None
#   im_class = None

    # @xxx: [bw] много быстрых и необдуманных правок

    # self.state:
    # 0: expecting a string with the method name
    # 1: expecting an instance (or None for unbound methods)
    # 2: expecting a class

    def checkToken(self, typebyte, size):
        if self.state == 0:
            if typebyte not in (tokens.STRING, tokens.SVOCAB):
                raise BananaError('MethodUnslicer methodname must be a STRING')

        elif self.state == 1:
            if typebyte != tokens.OPEN:
                raise BananaError('MethodUnslicer instance must be OPEN')

#       elif self.state == 2:
#           if typebyte != tokens.OPEN:
#               raise BananaError('MethodUnslicer class must be an OPEN')

    def doOpen(self, opentype):
        # check the opentype
        if self.state == 1:
            if opentype[0] not in (b'instance', b'none'):
                raise BananaError('MethodUnslicer instance must be instance or None')

#       elif self.state == 2:
#           if opentype[0] != b'class':
#               raise BananaError('MethodUnslicer class must be a class')

        unslicer = self.open(opentype)
        # TODO: apply constraint
        return unslicer

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None

        if self.state == 0:
            self.im_func = obj

        elif self.state == 1:
#           assert type(obj) in (InstanceType, type(None))
            assert obj is None or not inspect.isclass(obj), type(obj)
            self.im_self = obj

#       elif self.state == 2:
#           assert type(obj) == ClassType # TODO: new-style classes?
#           assert inspect.isclass(obj), type(obj)
#           assert self.im_self is None or isinstance(self.im_self, obj), (self.im_self, obj)
#           self.im_class = obj

        else:
            raise BananaError('MethodUnslicer only accepts three objects')

        self.state += 1

    def receiveClose(self):
#       if self.state != 3:
#           raise BananaError('MethodUnslicer requires three objects')

        if self.im_self is None:
            # getattr gives us an unbound method
#           meth = getattr(self.im_class, self.im_func)
            meth = reflect.namedAny(self.im_func)
            return meth, None

        # TODO: late-available instances
        #if isinstance(self.im_self, NotKnown):
        #    im = _InstanceMethod(self.im_name, self.im_self, self.im_class)
        #    return im

#       meth = vars(self.im_class)[self.im_func]
#       meth = vars(type(self.im_self))[self.im_func]
#       meth = meth.__get__(self.im_self)
        meth = getattr(self.im_self, self.im_func)
        return meth, None


class FunctionUnslicer(slicer.LeafUnslicer):
    opentype = (b'function',)
    unslicerRegistry = UnsafeUnslicerRegistry

    finished = False

    def checkToken(self, typebyte, size):
        if typebyte not in (tokens.STRING, tokens.SVOCAB):
            raise BananaError("FunctionUnslicer only accepts STRINGs")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None

        if self.finished:
            raise BananaError("FunctionUnslicer only accepts one string")

        self.finished = True
        # TODO: taste here!
        self.func = reflect.namedAny(obj)

    def receiveClose(self):
        if not self.finished:
            raise BananaError("FunctionUnslicer requires a string")
        return self.func, None


# the root unslicer for storage is just like the regular one, but hands
# received objects to the StorageBanana
class StorageRootUnslicer(ScopedRootUnslicer):
    def receiveChild(self, obj, ready_deferred):
        self.protocol.receiveChild(obj, ready_deferred)


# but the "unsafe" one has its own tables
class UnsafeStorageRootUnslicer(StorageRootUnslicer):
    # This version tracks references for the entire lifetime of the
    # protocol. It is most appropriate for single-use purposes, such as a
    # replacement for Pickle.
    topRegistries  = [slicer.UnslicerRegistry, slicer.BananaUnslicerRegistry, UnsafeUnslicerRegistry]
    openRegistries = [slicer.UnslicerRegistry, UnsafeUnslicerRegistry]


class StorageBanana(banana.Banana):
    object    = None
    violation = None
    disconnectReason = None
    slicerClass = StorageRootSlicer
    unslicerClass = StorageRootUnslicer

    def prepare(self):
        self.d = Deferred()
        return self.d

    def receiveChild(self, obj, ready_deferred):
        if ready_deferred:
            ready_deferred.addBoth(self.d.callback)
            self.d.addCallback(lambda res: obj)
        else:
            self.d.callback(obj)
        del self.d

    def receivedObject(self, obj):
        self.object = obj

    def sendError(self, msg):
        pass

    def reportViolation(self, why):
        self.violation = why

    def reportReceiveError(self, f):
        self.disconnectReason = f
        f.raiseException()


class SerializerTransport:
    def __init__(self, sio):
        self.sio = sio

    def write(self, data):
        self.sio.write(data)

    def loseConnection(self, why='ignored'):
        pass


def serialize(obj, outstream=None, root_class=StorageRootSlicer, banana=None):
    """Serialize an object graph into a sequence of bytes. Returns a Deferred
    that fires with the sequence of bytes."""
    if banana:
        b = banana
    else:
        b = StorageBanana()
        b.slicerClass = root_class

    if outstream is None:
        sio = io.BytesIO()
    else:
        sio = outstream

    b.transport = SerializerTransport(sio)
    b.connectionMade()
    d = b.send(obj)

    def _report_error(res):
        if b.disconnectReason:
            return b.disconnectReason
        if b.violation:
            return b.violation
        return res

    d.addCallback(_report_error)

    if outstream is None:
        d.addCallback(lambda res: sio.getvalue())
    else:
        d.addCallback(lambda res: outstream)

    return d


def unserialize(str_or_instream, banana=None, root_class=StorageRootUnslicer):
    """Unserialize a sequence of bytes back into an object graph."""
    if banana:
        b = banana
    else:
        b = StorageBanana()
        b.unslicerClass = root_class
    b.connectionMade()
    d = b.prepare() # this will fire with the unserialized object
    if isinstance(str_or_instream, str):
        b.dataReceived(str_or_instream)
    else:
        raise RuntimeError("input streams not implemented yet")
    def _report_error(res):
        if b.disconnectReason:
            return b.disconnectReason
        if b.violation:
            return b.violation
        return res # return the unserialized object
    d.addCallback(_report_error)
    return d

