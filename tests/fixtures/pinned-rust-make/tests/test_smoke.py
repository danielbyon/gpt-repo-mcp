import unittest


class SmokeTest(unittest.TestCase):
    def test_discovery(self):
        self.assertEqual(__name__, "test_smoke")
