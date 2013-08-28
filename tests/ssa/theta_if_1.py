""" Simple 'if' block

Starting form:
{
    a = 1;
    if (b == 0)
        a = 2;
    return a;
}

Expected SSA form:
{
loc_1:
    a@0 = 1;
    goto loc_2 if (b@1 != 0) else goto loc_3;

loc_2:
    a@2 = 2;
    goto loc_3;

loc_3:
    a@3 = THETA(a@0, a@2)
    return a@3;
}

"""

import sys
sys.path.append('../')
sys.path.append('../../src/')

from common.ply import ir_parser
from common.disassembler import parser_disassembler
from decompiler import decompiler_t
from output import c

text = """
        a = 1;
        if (b != 0) goto 300;
        a = 2;
300:    return a;
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
