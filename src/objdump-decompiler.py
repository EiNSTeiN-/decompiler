import sys
import re
import binascii
import traceback
import argparse
from collections import namedtuple, OrderedDict

import capstone

import decompiler
import host
import host.dis
import ssa
import output.c

class Cmdline(object):
  def __init__(self):
    self.functions = self.objdump_load(self.read_stdin())
    self.arch = 'x86'
    self.callconv = 'cdecl'
    self.step_until = decompiler.step_decompiled
    return

  def objdump_to_hex(self, input):
    hex = re.findall(r'^\s*[a-f0-9]*:((?:[\s\t](?:[a-f0-9]{2}))*)', input, flags=re.MULTILINE)
    hex = ''.join(hex).replace(' ', '').replace("\t", '')
    return binascii.unhexlify(hex)

  def objdump_load(self, data):
    parsed = re.findall(r'([a-f0-9]+) \<([^\>]+)\>\:\n((?:\s+[a-f0-9]+:(?:[\s\t](?:[a-f0-9]{2}))+[^\n]*)*\n)', data, flags=re.MULTILINE)
    Function = namedtuple('Function', ['address', 'name', 'text', 'hex'])
    functions = {o[1]: Function(address=int(o[0], 16),name=o[1],text=o[2],hex=self.objdump_to_hex(o[2])) for o in parsed}
    return functions

  def decompile_until(self, input):
    ssa.ssa_context_t.index = 0

    if self.arch == 'x86':
      md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
      dis = host.dis.available_disassemblers['capstone'].create(md, input)
    elif self.arch == 'x86-64':
      md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
      dis = host.dis.available_disassemblers['capstone'].create(md, input)
    else:
      raise RuntimeError('no such architecture: %s' % (self.arch, ))

    dec = decompiler.decompiler_t(dis, 0)
    dec.calling_convention = self.callconv
    dec.step_until(self.step_until)
    return dec

  def read_stdin(self):
    data = ''
    while True:
      try:
        line = sys.stdin.readline()
      except KeyboardInterrupt:
        break
      if not line:
        break
      data += line
    return data

  def print_function(self, function):
    print '----------'
    print '%x %s (%s)' % (function.address, function.name, self.step_until.__doc__)
    try:
      dec = self.decompile_until(function.hex)
      print(''.join([str(o) for o in output.c.tokenizer(dec.function).tokens]))
    except BaseException as e:
      print 'Failed to decompile: %s' % repr(e)
      traceback.print_exc()
    return

  def decompile_function(self, name):
    function = self.functions[name]
    self.print_function(function)
    return

  def decompile_all(self):
    for name, function in self.functions.iteritems():
      self.print_function(function)
    return

  @property
  def decompilation_steps(self):
    steps = OrderedDict()
    for subclass in decompiler.decompiler_t.STEPS:
      m = re.match(r'step_(.*)', subclass.__name__)
      if m:
        steps[m.group(1)] = subclass
    return steps

if __name__ == '__main__':
  p = Cmdline()

  parser = argparse.ArgumentParser(description='Decompiler')
  parser.add_argument('--arch', dest='arch', action='store',
                     default='x86',
                     help='assembly architecture (x86, x86-64)')
  parser.add_argument('--conv', dest='callconv', action='store',
                     default='cdecl',
                     help='calling convention (cdecl, )')
  parser.add_argument('--step', dest='step', action='store',
                     default='decompiled',
                     help='show decompilation step (default: decompiled)')
  parser.add_argument('--fct', dest='function', action='store',
                     default=None,
                     help='name of target function')

  args = parser.parse_args()

  p.arch = args.arch
  p.callconv = args.callconv

  steps = p.decompilation_steps
  if args.step.isdigit():
    p.step_until = steps.values()[int(args.step)]
  elif args.step in steps:
    p.step_until = steps[args.step]
  else:
    print 'argument --step not valid, choose one of:'
    for name in steps:
      print '  %-30s %s' % (name, steps[name].__doc__)
    sys.exit(1)

  if not args.function:
    p.decompile_all()
  elif args.function in p.functions:
    p.decompile_function(args.function)
  else:
    print 'argument --fct not valid, use one of:'
    print '   %s' % (', '.join([f.name for f in p.functions.values()]))
    sys.exit(1)

  sys.exit(0)
