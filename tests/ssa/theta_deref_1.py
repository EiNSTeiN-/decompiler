""" Simple dereference with THETA-functions in SSA form.

Starting form:
{
    if (*(s+4) == 0)
        *(s+4) = 1;
    return *(s+4);
}

Expected SSA form:
{
loc_1:
    goto loc_3 if (*(s@0 + 4)@3 != 0) else goto loc_2;

loc_2:
    s@1 = THETA(s@0)
    *(s@1 + 4)@4 = 1;
    goto loc_3;

loc_3:
    s@2 = THETA(s@0, s@1)
    *(s@2 + 4)@5 = THETA(*(s@0 + 4)@3, *(s@1 + 4)@4)
    return *(s@2 + 4)@5;
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
        if(*(s+4) == 0) goto 300;
        *(s+4) = 1;
300:    return *(s+4);
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
