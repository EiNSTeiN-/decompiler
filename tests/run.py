# coding=utf-8

import unittest
import sys

loader = unittest.TestLoader()
suite = loader.discover('tests/unit/', pattern='test_*.py')

runner = unittest.TextTestRunner(descriptions=True, verbosity=3)
result = suite.run(runner._makeResult())

if not result.wasSuccessful():
  print 'not successful'

  for cls, error in result.errors:
    print '------------------------------'
    print 'Error:', repr(cls)
    print '------------------------------'
    print error
    print

  for cls, error in result.failures:
    print '------------------------------'
    print 'Failure:', repr(cls)
    print '------------------------------'
    print error
    print

  sys.exit(1)
