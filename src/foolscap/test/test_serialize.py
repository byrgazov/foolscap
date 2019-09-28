# -*- test-case-name: foolscap.test.test_serialize -*-

import gc
import io

from twisted.trial import unittest
from twisted.application import service

from foolscap.api import Referenceable, Copyable, RemoteCopy
from foolscap.api import flushEventualQueue, serialize, unserialize, Tub
from foolscap.referenceable import RemoteReference
from foolscap.tokens import Violation
from foolscap.util import allocate_tcp_port
from foolscap.test.common import ShouldFailMixin


class Foo:
    # instances of non-Copyable classes are not serializable
    pass


class Bar(Copyable, RemoteCopy):
    # but if they're Copyable, they're ok
    typeToCopy = 'bar'
    copytype   = 'bar'


class Serialize(unittest.TestCase, ShouldFailMixin):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d

    def NOT_test_data_synchronous(self):
        obj = ['look at the pretty graph', 3, True]
        obj.append(obj) # and look at the pretty cycle
        data = serialize(obj)
        obj2 = unserialize(data)
        self.assertEqual(obj2[1], 3)
        self.assertIs(obj2[3], obj2)

    def test_data(self):
        obj = ['simple graph', 3, True]

        d = serialize(obj)
        d.addCallback(unserialize)

        def _check(obj2):
            self.assertEqual(obj2[1], 3)

        return d.addCallback(_check)

    def test_cycle(self):
        obj = ['look at the pretty graph', 3, True]
        obj.append(obj) # and look at the pretty cycle

        d = serialize(obj)
        d.addCallback(unserialize)

        def _check(obj2):
            self.assertEqual(obj2[1], 3)
            self.assertIs(obj2[3], obj2)

        return d.addCallback(_check)

    def test_copyable(self):
        obj = ['fire pretty', Bar()]

        d = serialize(obj)
        d.addCallback(unserialize)

        def _check(obj2):
            self.assertTrue(isinstance(obj2[1], Bar))
            self.failIfIdentical(obj[1], obj2[1])

        return d.addCallback(_check)
    test_copyable.timeout = 2

    def test_data_outstream(self):
        obj = ['look at the pretty graph', 3, True]
        obj.append(obj) # and look at the pretty cycle

        b = io.BytesIO()
        d = serialize(obj, outstream=b)

        def _out(res):
            self.assertIs(res, b)
            return b.getvalue()

        d.addCallback(_out)
        d.addCallback(lambda data: unserialize(data))

        def _check(obj2):
            self.assertEqual(obj2[1], 3)
            self.assertIs(obj2[3], obj2)

        return d.addCallback(_check)

    def test_unhandled_objects(self):
        obj1 = [1, Referenceable()]
        d = self.shouldFail(Violation, "1",
                            "This object can only be serialized by a broker",
                            serialize, obj1)
        obj2 = [1, Foo()]

        return d.addCallback(lambda ign:
            self.shouldFail(Violation, "2",
                "cannot serialize <foolscap.test.test_serialize.Foo object",
                serialize, obj2))

    def test_referenceable(self):
        t1 = Tub()
        t1.setServiceParent(self.s)

        portnum = allocate_tcp_port()

        t1.listenOn('tcp:%d:interface=127.0.0.1' % portnum)
        t1.setLocation('127.0.0.1:%d' % portnum)

        r1 = Referenceable()

        # the serialized blob can't keep the reference alive, so you must
        # arrange for that separately

        t1.registerReference(r1)

        t2 = Tub()
        t2.setServiceParent(self.s)

        obj = ('graph tangly', r1)
        d = t1.serialize(obj)

        del r1, obj

        def _done(data):
            self.assertIn(b'their-reference', data)
            return data

        d.addCallback(_done)
        d.addCallback(t2.unserialize)

        def _check(obj2):
            self.assertEqual(obj2[0], 'graph tangly')
            self.assertTrue(isinstance(obj2[1], RemoteReference))

        return d.addCallback(_check)
    test_referenceable.timeout = 5

    def test_referenceables_die(self):
        # serialized data will not keep the referenceable alive
        t1 = Tub()
        t1.setServiceParent(self.s)

        portnum = allocate_tcp_port()

        t1.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t1.setLocation("127.0.0.1:%d" % portnum)

        t2 = Tub()
        t2.setServiceParent(self.s)

        r1  = Referenceable()
        obj = ("graph tangly", r1)
        d   = t1.serialize(obj)

        del r1, obj

        gc.collect()

        return d.addCallback(lambda data:
            self.shouldFail(KeyError, "test_referenceables_die",
                "unable to find reference for name",
                t2.unserialize, data))
    test_referenceables_die.timeout = 5
