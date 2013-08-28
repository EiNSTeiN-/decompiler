""" Simple dereference with aliasing with THETA-functions in SSA form.

Starting form:
{
    a = s + 4;
    if (*(s + 8) == 0) {
        c = 4;
        *(a + c) = *(s + 8) + 1;
    }
    return *(a + 4);
}

Expected SSA form:
{
loc_1:
    a@1 = s@0;
    goto loc_2 if (*(s@0 + 8)@6 == 0) else goto loc_3;

loc_2:
    c@2 = 4;
    s@3 = THETA(s@0);
    a@4 = THETA(a@1);
    *(s@3 + 8)@7 = THETA(*(s@0 + 8)@6);
    *(a@4 + c@2)@8 = *(s@3 + 8)@7 + 1;
    goto loc_3;

loc_3:
    a@5 = THETA(a@1, a@4);
    *(a@5 + 4)@9 = THETA(*(a@4 + c@2)@8, *(s@0 + 8)@6);
    return *(a@5 + 4)@9;
}

Check that *(s + 8), *(a + c) and *(a + 4) are correctly aliased and get the same index.

"""

import sys
sys.path.append('../')
sys.path.append('../../src/')

from common.ply import ir_parser
from common.disassembler import parser_disassembler
from decompiler import decompiler_t
from output import c

text = """
        a = s + 4;
        if (*(s + 8) != 0) goto 300;
        
        c = 4;
        *(a + c) = *(s + 8) + 1;
        
300:    return *(a + 4);
"""
dis = parser_disassembler(text)
d = decompiler_t(dis, 0)

for step in d.steps():
    print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])

t = c.tokenizer(d.flow)
tokens = list(t.flow_tokens())

print ''.join([str(t) for t in tokens])
