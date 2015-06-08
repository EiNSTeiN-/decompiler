# coding=utf-8

import unittest
import re
import binascii

from test_helper import *
import decompiler
import ssa

class TestLoops(TestHelper):

  def setUp(self):
    TestHelper.setUp(self)
    self.functions_x86 = self.objdump_load('../data/loops-x86-objdump')
    #self.functions_x86_64 = self.objdump_load('../data/loops-x64-objdump')
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop0_x86(self):
    fct = self.functions_x86['loop0']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = a0;
        while (1) {
          s1 = s1 + 1;
          -307(134515040, s1);
        }
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop1_x86(self):
    fct = self.functions_x86['loop1']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 29) {
          -339(134515040, s0);
          s0 = s0 + 1;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop2_x86(self):
    fct = self.functions_x86['loop2']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 9) {
          s0 = s0 + 1;
          -391(134515040, s0);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop3_x86(self):
    fct = self.functions_x86['loop3']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        v0 = 0;
        do {
          s0 = v0;
          v0 = s0 + 1;
          -443(134515040, s0);
        } while(v0 <= 9);
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop4_x86(self):
    fct = self.functions_x86['loop4']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 29) {
          if (s0 == 4) {
            -477(134515044);
          }
          else if (s0 != 12) {
            -493(134515040, s0);
          }
          s0 = s0 + 1;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop5_x86(self):
    fct = self.functions_x86['loop5']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        v0 = 0;
        goto loc_40;

      loc_40:
        s0 = v0;
        v0 = s0 + 1;
        if (s0 != 10) {
          if (v0 == 5) {
            -558(134515049);
          }
          else if (v0 != 12) {
            -574(134515040, v0);
          }
          goto loc_40;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop6_x86(self):
    fct = self.functions_x86['loop6']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        do {
          if (s0 != 6) {
            -660(134515040, s0);
          }
          else {
            -644(134515054);
          }
          s0 = s0 + 1;
        } while(s0 <= 9);
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop7_x86(self):
    fct = self.functions_x86['loop7']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        goto loc_3b;

      loc_3b:
        if (s0 <= 29) {
          if (s0 != 7) {
            -735(134515040, s0);
            s0 = s0 + 1;
            goto loc_3b;
          }
          -719(134515058);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop8_x86(self):
    fct = self.functions_x86['loop8']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        v0 = 0;
        goto loc_37;

      loc_37:
        s0 = v0;
        v0 = s0 + 1;
        if (s0 <= 9) {
          if (v0 != 8) {
            -807(134515040, v0);
            goto loc_37;
          }
          -791(134515064);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop9_x86(self):
    fct = self.functions_x86['loop9']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        do {
          if (s0 == 9) {
            -868(134515071);
            goto loc_44;
          }
          -884(134515040, s0);
          s0 = s0 + 1;
        } while(s0 <= 9);
        goto loc_44;

      loc_44:
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop10_x86(self):
    fct = self.functions_x86['loop10']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        goto loc_5d;

      loc_59:
        s0 = s0 + 1;
        goto loc_5d;

      loc_5d:
        if (s0 <= 29) {
          if (s0 != 4) {
            if (s0 == 12) {
              *s4 = 18;
              goto loc_59;
            }
            if (s0 == 6) {
              *s4 = 10;
              goto loc_59;
            }
          }
          else {
            -943(134515044);
          }
          -959(134515040, s0);
          goto loc_59;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop11_x86(self):
    fct = self.functions_x86['loop11']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 29) {
          s2 = 0;
          while (s2 <= 29) {
            -1065(134515076, s2, s0);
            s2 = s2 + 1;
          }
          s2 = 0;
          while (s2 <= 29) {
            -1065(134515076, s2, s0);
            s2 = s2 + 1;
          }
          s0 = s0 + 1;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop12_x86(self):
    fct = self.functions_x86['loop12']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        goto loc_69;

      loc_4b:
        if (s2 <= 29) {
          if (s2 != 8) {
            -1189(134515076, s2, s0);
            s2 = s2 + 1;
            goto loc_4b;
          }
          -1173(134515082);
        }
        -1189(134515040, s0);
        s0 = s0 + 1;
        goto loc_69;

      loc_69:
        if (s0 <= 29) {
          s2 = 0;
          goto loc_4b;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop13_x86(self):
    fct = self.functions_x86['loop13']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 29) {
          do {
            s2 = s2 + 1;
            -1307(134515040, s2);
          } while(s2 <= 9);
          -1307(134515040, s0);
          s0 = s0 + 1;
        }
        return 0;
      }
      """)
    return

if __name__ == '__main__':
  unittest.main()
