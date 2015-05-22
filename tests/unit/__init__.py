# coding=utf-8

import os
import sys

sys.path.append('./tests')
sys.path.append('./src')

files = os.listdir(os.path.dirname(__file__))
__all__ = [name[:-3] for name in files if name.startswith('test_') and name.endswith('.py')]
