import traceback

try:
  import idaapi # try importing ida's main module.

  print 'Using IDA backend.'
  from .ida.ui import *
except BaseException as e:
  print repr(e)
  traceback.print_exc()
