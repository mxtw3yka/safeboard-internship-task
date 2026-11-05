import unittest

from tool import version_in_range


class VersionRangeTests(unittest.TestCase):
    def test_inclusive_start_exclusive_fix_and_zero_padding(self):
        self.assertTrue(version_in_range("15", "15.0.0", "15.4.1"))
        self.assertTrue(version_in_range("15.4", "15", "15.4.1"))
        self.assertFalse(version_in_range("15.4.1", "15", "15.4.1"))
        self.assertFalse(version_in_range("14.9.9", "15", "15.4.1"))

    def test_numeric_components_not_lexicographic_order(self):
        self.assertTrue(version_in_range("9.0.10", "9.0.9", "9.0.11"))
        self.assertFalse(version_in_range("9.0.9", "9.0.10", "9.0.11"))


if __name__ == "__main__":
    unittest.main()
