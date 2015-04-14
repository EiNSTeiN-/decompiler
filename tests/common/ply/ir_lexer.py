import ply.lex as lex

reserved = {
  'if' : 'IF',
  'goto' : 'GOTO',
  'return' : 'RETURN',
}

# List of token names.   This is always required
tokens = [
  'ID',
  'COMMENT',
  'NUMBER',
  'STRING',

  'B_AND', # &&
  'B_OR', # ||
  'B_EQ', # ==
  'B_NEQ', # !=
  'B_LEQ', # <=
  'B_AEQ', # >=
  'SHL', # <<
  'SHR', # >>
] + reserved.values()

literals = "():<>~!&,+-*/=^|?;"

def t_ID(t):
  r'[a-zA-Z_][a-zA-Z0-9_]*(@[0-9]+)?'
  t.type = reserved.get(t.value,'ID')    # Check for reserved words
  return t

def t_COMMENT(t):
  r'\/\/.*'
  pass
  # No return value. Token discarded

def t_NUMBER(t):
  r'\d+'
  t.value = int(t.value)
  return t

def t_STRING(t):
  r"""\"(?:(?:\\"|[^"\n])*)\""""
  #~ t.value = t.value
  return t


# Regular expression rules for simple tokens
t_B_AND = r'&&'
t_B_OR = r'\|\|'
t_B_EQ = r'=='
t_B_NEQ = r'!='
t_B_LEQ = r'<='
t_B_AEQ = r'>='
t_SHL = r'<<'
t_SHR = r'>>'

# Define a rule so we can track line numbers
def t_newline(t):
  r'\n+'
  t.lexer.lineno += len(t.value)

# A string containing ignored characters (spaces and tabs)
t_ignore  = ' \t'

# Error handling rule
def t_error(t):
  assert 0, "Illegal character '%s'" % t.value[0]
  #~ t.lexer.skip(1)


lexer = lex.lex()

if __name__ == '__main__':

  lexer.input("""
  loc_1:
    a = 400 // foo
    b = a - 900 + -100
    // bar
    c = *(a + 4)
    d = "blarg"
  """)

  # Tokenize
  while True:
    tok = lexer.token()
    if not tok: break      # No more input
    print tok
