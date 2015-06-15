import ply.yacc as yacc
import ir_lexer

from expressions import *
from statements import *

tokens = ir_lexer.tokens

next_register = 0
registers = {}
next_method = 0x800000
methods = {}

def p_expression_plus(p):
  'expression : expression "+" expression'
  p[0] = add_t(p[1], p[3])

def p_expression_minus(p):
  'expression : expression "-" expression'
  p[0] = sub_t(p[1], p[3])

def p_expression_mul(p):
  'expression : expression "*" expression'
  p[0] = mul_t(p[1], p[3])

def p_expression_div(p):
  'expression : expression "/" expression'
  p[0] = div_t(p[1], p[3])

def p_expression_shl(p):
  'expression : expression SHL expression'
  p[0] = shl_t(p[1], p[3])

def p_expression_shr(p):
  'expression : expression SHR expression'
  p[0] = shr_t(p[1], p[3])

def p_expression_xor(p):
  'expression : expression "^" expression'
  p[0] = xor_t(p[1], p[3])

def p_expression_and(p):
  'expression : expression "&" expression'
  p[0] = and_t(p[1], p[3])

def p_expression_or(p):
  'expression : expression "|" expression'
  p[0] = or_t(p[1], p[3])

def p_expression_b_and(p):
  'expression : expression B_AND expression'
  p[0] = b_add_t(p[1], p[3])

def p_expression_b_or(p):
  'expression : expression B_OR expression'
  p[0] = b_or_t(p[1], p[3])

def p_expression_b_eq(p):
  'expression : expression B_EQ expression'
  p[0] = eq_t(p[1], p[3])

def p_expression_b_neq(p):
  'expression : expression B_NEQ expression'
  p[0] = neq_t(p[1], p[3])

def p_expression_b_leq(p):
  'expression : expression B_LEQ expression'
  p[0] = leq_t(p[1], p[3])

def p_expression_b_aeq(p):
  'expression : expression B_AEQ expression'
  p[0] = aeq_t(p[1], p[3])

def p_expression_lt(p):
  'expression : expression "<" expression'
  p[0] = lower_t(p[1], p[3])

def p_expression_gt(p):
  'expression : expression ">" expression'
  p[0] = above_t(p[1], p[3])

def p_expression_ternary_if(p):
  'expression : expression "?" expression ":" expression %prec TERNARY'
  p[0] = ternary_if_t(p[1], p[3], p[5])

def p_expression_paren(p):
  'expression : "(" expression ")"'
  p[0] = p[2]

def p_expression_uminus(p):
  'expression : "-" expression %prec UNARY'
  p[0] = neg_t(p[2])

def p_expression_uplus(p):
  'expression : "+" expression %prec UNARY'
  p[0] = p[2]

def p_expression_not(p):
  'expression : "~" expression %prec UNARY'
  p[0] = not_t(p[2])

def p_expression_neg(p):
  'expression : "!" expression %prec UNARY'
  p[0] = b_not_t(p[2])

def p_expression_address(p):
  'expression : "&" expression %prec UNARY'
  p[0] = address_t(p[2])

def p_expression_identifier(p):
  'expression : assignable'
  p[0] = p[1]

def p_expression_call(p):
  'expression : call'
  p[0] = p[1]

def p_expression_number(p):
  'expression : NUMBER'
  p[0] = value_t(p[1], 32)

def p_arg_expression(p):
  'arg : expression'
  p[0] = p[1]

def p_arglist_comma(p):
  'arglist : arglist "," arg'
  p[0] = p[1] + [p[3]]

def p_arglist_arg(p):
  'arglist : arg'
  p[0] = [p[1]]

def p_arglist_empty(p):
  'arglist :'

def p_call(p):
  'call : ID "(" arglist ")"'
  global next_register
  global next_method
  if p[1] not in methods:
    methods[p[1]] = next_method
    next_method += 1
  if 'esp' not in registers:
    registers['esp'] = next_register
    next_register += 1
  args = params_t(*(p[3] or []))
  stack = regloc_t(registers['esp'], size=32, name='esp')
  p[0] = call_t(value_t(methods[p[1]], 32), stack, args)

def p_deref(p):
  'deref : "*" expression %prec UNARY'
  p[0] = deref_t(p[2], 32)

def p_assignable_deref(p):
  'assignable : deref'
  p[0] = p[1]

def p_assignable_identifier(p):
  'assignable : ID'
  global next_register
  if p[1] not in registers:
    registers[p[1]] = next_register
    next_register += 1
  p[0] = regloc_t(registers[p[1]], 32, p[1])

def p_assignee_expression(p):
  'assignee : expression'
  p[0] = p[1]

def p_assign(p):
  'assign : assignable "=" assignee'
  p[0] = assign_t(p[1], p[3])

def p_return_expression(p):
  'return : RETURN expression'
  p[0] = return_t(None, p[2])

def p_return_empty(p):
  'return : RETURN'
  p[0] = return_t(None)

#~ def p_goto_assignable(p):
  #~ 'goto : GOTO assignable'
  #~ p[0] = goto_t(p[2])

def p_goto_number(p):
  'goto : GOTO NUMBER'
  p[0] = goto_t(None, value_t(p[2], 32))

class conditional_goto_t(object):
  def __init__(self, cond, loc):
    self.cond = cond
    self.loc = loc
    return
  def __repr__(self):
    return '<goto %u if %s>' % (self.loc, repr(self.cond))

def p_branch(p):
  'branch : IF "(" expression ")" GOTO NUMBER'
  p[0] = conditional_goto_t(p[3], p[6])

def p_statement_inner(p):
  '''statement_inner : expression
                     | assign
                     | return
                     | goto
                     | branch'''
  p[0] = p[1]

def p_statement_number(p):
  'statement : NUMBER ":" statement_inner ";"'
  p[0] = p[1], p[3]

def p_statement_plain(p):
  'statement : statement_inner ";"'
  p[0] = None, p[1]

def p_statements_recursive(p):
  'statements : statements statement'
  p[1].append(p[2])
  p[0] = p[1]

def p_statements(p):
  'statements : statement'
  p[0] = [p[1], ]

def p_error(p):
  raise RuntimeError("Syntax error in input: %s" % (repr(p), ))

start = 'statements'

precedence = (
  #~ ('nonassoc', '<', '>', '<=', '>='),  # Nonassociative operators.
  ('right', 'TERNARY'),
  ('left', 'B_OR'),
  ('left', 'B_AND'),
  ('left', '|'),
  ('left', '^'),
  ('left', '&'),
  ('left', 'B_EQ', 'B_NEQ'),
  ('left', '<', '>', 'B_LEQ', 'B_AEQ'),
  ('left', 'SHL', 'SHR'),
  ('left', '+', '-'),
  ('left', '*', '/'),
  ('right', 'UNARY'),            # Unary operators
)

parser = yacc.yacc()

def parse(text):
  return parser.parse(text, lexer=ir_lexer.lexer)

if __name__ == '__main__':

  #~ sys.path.append('../../src/')

  text = """
  100:
    a = 400; // foo
    b = a - 900 + -100;
    // bar
    c = *(a + 4);
  """

  print parse(text)

