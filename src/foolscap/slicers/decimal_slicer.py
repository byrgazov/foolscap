# -*- test-case-name: foolscap.test.test_banana -*-

import decimal
from twisted.internet.defer import Deferred
from foolscap.tokens import BananaError, STRING, SVOCAB
from foolscap.slicer import BaseSlicer, LeafUnslicer
from foolscap.constraint import Any


class DecimalSlicer(BaseSlicer):
    opentype = (b'decimal',)
    slices = decimal.Decimal

    def sliceBody(self, streamable, banana):
        yield str(self.obj)


class DecimalUnslicer(LeafUnslicer):
    opentype   = (b'decimal',)
    value      = None
    constraint = None

    def setConstraint(self, constraint):
        if not isinstance(constraint, Any):
            raise BananaError('DecimalUnslicer does not currently accept a constraint')

    def checkToken(self, typebyte, size):
        if typebyte not in (STRING, SVOCAB):
            raise BananaError('DecimalUnslicer only accepts strings')

        #if self.constraint:
        #    self.constraint.checkToken(typebyte, size)

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None

        if self.value is not None:
            raise BananaError('already received a string')

        self.value = decimal.Decimal(obj)

    def receiveClose(self):
        return self.value, None

    def describe(self):
        return '<unicode>'
