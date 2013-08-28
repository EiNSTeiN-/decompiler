""" Simple 'if-then-else' block

Starting form:
{
    if (a == 0)
        a = 1;
    else
        a = 2;
    return a;
}

Expected SSA form:
{
loc_1:
    goto loc_2 if (a@1 == 0) else goto loc_3;

loc_2:
    a@2 = 1;
    goto loc_4;

loc_3:
    a@3 = 2
    goto_loc_4;

loc_4:
    a@4 = THETA(a@2, a@3)
    return a@4;
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
        if (a == 0) goto 200;
        a = 2;
        goto 300;
200:    a = 1;
300:    return a;
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
