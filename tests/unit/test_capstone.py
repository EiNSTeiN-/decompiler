import unittest
import sys

sys.path.append('./tests')
sys.path.append('./src')
import capstone

import ssa
import host.dis
import test_helper
import decompiler

class TestCapstone(test_helper.TestHelper):

  def __init__(self, *args):
    test_helper.TestHelper.__init__(self, *args)
    self.code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    self.code64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"

  def decompile_until(self, mode, input, last_step):
    ssa.ssa_context_t.index = 0
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    dis = host.dis.available_disassemblers['capstone'].create(md, input)
    dec = decompiler.decompiler_t(dis, 0)
    dec.step_until(last_step)
    return dec

  def assert_ir(self, mode, input, expected):
    d = self.decompile_until(mode, input, decompiler.step_ir_form)
    result = self.tokenize(d.flow)
    expected = self.unindent(expected)
    self.assertMultiLineEqual(result, expected)
    return

  def test_code32(self):

    expected = """
      ecx = edx + esi + 8;
      %eflags.expr = eax + ebx;
      %eflags.cf = %eflags.expr < 0;
      %eflags.pf = PARITY(%eflags.expr);
      %eflags.af = ADJUST(%eflags.expr);
      %eflags.zf = !%eflags.expr;
      %eflags.sf = SIGN(%eflags.expr);
      %eflags.of = OVERFLOW(%eflags.expr);
      eax = eax + ebx;
      %eflags.expr = esi + 4660;
      %eflags.cf = %eflags.expr < 0;
      %eflags.pf = PARITY(%eflags.expr);
      %eflags.af = ADJUST(%eflags.expr);
      %eflags.zf = !%eflags.expr;
      %eflags.sf = SIGN(%eflags.expr);
      %eflags.of = OVERFLOW(%eflags.expr);
      esi = esi + 4660;
      %eflags.expr = eax + 291;
      %eflags.cf = %eflags.expr < 0;
      %eflags.pf = PARITY(%eflags.expr);
      %eflags.af = ADJUST(%eflags.expr);
      %eflags.zf = !%eflags.expr;
      %eflags.sf = SIGN(%eflags.expr);
      %eflags.of = OVERFLOW(%eflags.expr);
      eax = eax + 291;
      eax = *(ecx + edx * 4 + 291);
      %eflags.expr = ecx + 1;
      %eflags.pf = PARITY(%eflags.expr);
      %eflags.af = ADJUST(%eflags.expr);
      %eflags.zf = !%eflags.expr;
      %eflags.sf = SIGN(%eflags.expr);
      %eflags.of = OVERFLOW(%eflags.expr);
      ecx = ecx + 1;
      eax = ecx + edi + 26505;
      eax = edi + 26505;
      ah = -58;
    """

    self.assert_ir(capstone.CS_MODE_32, self.code32, expected)
    return

if __name__ == '__main__':
  unittest.main()


