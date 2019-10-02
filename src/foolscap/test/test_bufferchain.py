
from twisted.trial import unittest
from foolscap.banana import BufferChain


class T(unittest.TestCase):
    def test_al(self):
        c = BufferChain()
        c.append(b'ab')
        self.assertEqual(len(c), 2)
        c.append(b'')
        self.assertEqual(len(c), 2)
        c.append(b'c')
        self.assertEqual(len(c), 3)

    def test_bytes(self):
        c = BufferChain()
        c.append(b'ab')
        c.append(b'c')
        self.assertEqual(bytes(c), b'abc')

    def test_popleft(self):
        c = BufferChain()
        c.append(b'ab')
        s = c.popleft(1)
        self.assertEqual(s, b'a')
        self.assertEqual(bytes(c), b'b')
        s = c.popleft(1)
        self.assertEqual(s, b'b')
        self.assertEqual(bytes(c), b'')

        c.append(b'abc')
        s = c.popleft(1)
        self.assertEqual(s, b'a')
        self.assertEqual(bytes(c), b'bc')
        s = c.popleft(1)
        self.assertEqual(s, b'b')
        self.assertEqual(bytes(c), b'c')
        s = c.popleft(1)
        self.assertEqual(s, b'c')
        self.assertEqual(bytes(c), b'')

        c.append(b'abc')
        s = c.popleft(2)
        self.assertEqual(s, b'ab')
        self.assertEqual(bytes(c), b'c')
        s = c.popleft(1)
        self.assertEqual(s, b'c')
        self.assertEqual(bytes(c), b'')

        c.append(b'ab')
        c.append(b'c')
        s = c.popleft(2)
        self.assertEqual(s, b'ab')
        self.assertEqual(bytes(c), b'c')
        s = c.popleft(1)
        self.assertEqual(s, b'c')
        self.assertEqual(bytes(c), b'')

        c.append(b'a')
        c.append(b'bc')
        s = c.popleft(2)
        self.assertEqual(s, b'ab')
        self.assertEqual(bytes(c), b'c')
        s = c.popleft(1)
        self.assertEqual(s, b'c')
        self.assertEqual(bytes(c), b'')

        c.append(b'abc')
        s = c.popleft(4) # We just silently pop them all.
        self.assertEqual(s, b'abc')
        self.assertEqual(bytes(c), b'')

    def test_appendleft(self):
        c1 = BufferChain()
        c1.append(b'abcd')
        c1.appendleft(b'ef')
        self.assertEqual(bytes(c1),b'efabcd')
        s = c1.popleft(1)
        self.assertEqual(s, b'e')
        s = c1.popleft(2)
        self.assertEqual(s, b'fa')
        s = c1.popleft(3)
        self.assertEqual(s, b'bcd')

        c1 = BufferChain()
        c1.append(b'abcd')
        c1.popleft(1)
        c1.appendleft(b'ef')
        self.assertEqual(bytes(c1),b'efbcd')
        s = c1.popleft(1)
        self.assertEqual(s, b'e')
        s = c1.popleft(2)
        self.assertEqual(s, b'fb')
        s = c1.popleft(3)
        self.assertEqual(s, b'cd')

    def test_clear(self):
        c1 = BufferChain()
        c1.append(b'abcd')
        c1.clear()
        self.assertEqual(bytes(c1), b'')
