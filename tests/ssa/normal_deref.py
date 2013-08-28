""" Simple dereference tagging in SSA form.

Starting form:
{
    *(s+4) = 1;
    *(s+8) = 2;
    *(s+4) = *(s+4) + *(s+8);
    return *(s+4);
}

Expected SSA form:
{
loc_1:
    *(s@0 + 4)@1 = 1;
    *(s@0 + 8)@2 = 2;
    *(s@0 + 4)@3 = *(s@0 + 4)@1 + *(s@0 + 8)@2;
    return *(s@0 + 4)@3;
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
*(s+4) = 1;
*(s+8) = 2;
*(s+4) = *(s+4) + *(s+8);
return *(s+4);
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
