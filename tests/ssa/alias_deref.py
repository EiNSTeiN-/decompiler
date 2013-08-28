""" Simple dereference tagging in SSA form with aliasing.

Starting form:
{
    a = s;
    *(a + 8) = 1;
    s = s + 4;
    return *(s + 4);
}

Expected SSA form:
{
loc_1:
    a@1 = s@0;
    *(a@1 + 8)@3 = 1;
    s@2 = s@0 + 4
    return *(s@2 + 4)@3;
}

Check that *(a + 8) and *(s + 4) are correctly aliased and get the same index.

"""

import sys
sys.path.append('../')
sys.path.append('../../src/')

from common.ply import ir_parser
from common.disassembler import parser_disassembler
from decompiler import decompiler_t
from output import c

text = """
a = s;
*(a + 8) = 1;
s = s + 4;
return *(s + 4);
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
