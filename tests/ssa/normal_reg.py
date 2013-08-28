""" Simple register tagging in SSA form.

Starting form:
{
    a = 1;
    b = 2;
    a = a + b;
    return a;
}

Expected SSA form:
{
loc_1:
    a@0 = 1;
    b@1 = 2;
    a@2 = a@0 + b@1;
    return a@2;
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
b = 2;
a = a + b;
return a;
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
