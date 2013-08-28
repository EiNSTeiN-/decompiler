""" Simple while loop

Starting form:
{
    i = 0;
    while (i < 100) {
        i = i + 1;
    }
    return i;
}

Expected SSA form:
{
loc_1:
    i@0 = 0
    goto loc_2;

loc_2:
    i@1 = THETA(i@0, i@3)
    goto loc_3 if (i@1 < 100) else goto loc_4;

loc_3:
    i@2 = THETA(i@1)
    i@3 = i@2 + 1;
    goto loc_2;

loc_4:
    i@4 = THETA(i@1)
    return i@4;
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
100:    if (i >= 100) goto 400;
        i = i + 1;
        goto 100;
400:    return i;
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
