import unittest
import sys

loader = unittest.TestLoader()
suite = loader.discover('tests/unit/', pattern='test_*.py')

result = unittest.TextTestRunner(descriptions=True, verbosity=2)
suite.run(result._makeResult())
