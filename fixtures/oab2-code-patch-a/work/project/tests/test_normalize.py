import unittest

from project.normalize import normalize_identifier


class NormalizeTests(unittest.TestCase):
    def test_collapses_whitespace_and_dashes(self):
        self.assertEqual('alpha-beta', normalize_identifier(' Alpha   Beta '))

    def test_removes_non_ascii_punctuation(self):
        self.assertEqual('zone-7', normalize_identifier('Zone! 7'))


if __name__ == '__main__':
    unittest.main()
