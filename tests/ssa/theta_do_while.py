""" Simple do-while loop with THETA-functions.

Starting form:
{
    i = 0;
    do {
        i = i + 1;
    } while (i < 100);
    return i;
}

Expected SSA form:
{
loc_1:
    i@0 = 0
    goto loc_2;

loc_2:
    i@1 = THETA(i@0, i@2)
    i@2 = i@1 + 1;
    goto loc_2 if (i@2 < 100) else goto loc_3;

loc_3:
    i@3 = THETA(i@2)
    return i@3;
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
        i = 0;
200:    i = i + 1;
        if (i < 100) goto 200;
        return i;
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
