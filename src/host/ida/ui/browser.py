""" Browser widget for graph_t object.

"""

import idc

from output import c

try:
  import PySide
  from PySide import QtCore, QtGui
except:
  print 'PySide not available'
  raise

class token_fragment(object):

  def __init__(self, fragment, token):
    self.fragment = fragment
    self.token = token
    return

class FlowBrowser(QtGui.QTextEdit):

  def __init__(self, parent=None):

    QtGui.QTextEdit.__init__(self, parent)
    self.flow = None

    self.inserting = False
    self.cursorPositionChanged.connect(self.select_token)

    self.__fragments = []
    self.__textmap = {}
    self.__current_highlight = None

    return

  def select_token(self):
    """ callback for new selected element in the textedit box. """

    if self.inserting:
        return

    cursor = self.textCursor()
    fmt = cursor.charFormat()
    tok = fmt.property(QtGui.QTextFormat.UserProperty)

    if self.__current_highlight:
      brush = QtGui.QBrush(QtGui.QColor(0,0,0,0))
      self.set_fragments_bg(self.__current_highlight, brush)
      self.__current_highlight = None

    # avoid highlighting whitespaces
    s = str(tok)
    if s.strip() == '' or s in (';', '='):
      return

    if type(tok) in (c.token_lmatch, c.token_rmatch):
      other = tok.lmatch if type(tok) == c.token_rmatch else tok.rmatch
      token_fragments = [tf for tf in self.__fragments if tf.token in (other, tok)]
    elif s in self.__textmap:
      token_fragments = self.__textmap[s]
    else:
      return

    brush = QtGui.QBrush(QtGui.QColor(0xff,0xff,0x00,200))
    self.set_fragments_bg(token_fragments, brush)
    self.__current_highlight = token_fragments

    return

  def set_fragments_bg(self, token_fragments, brush):
    """ given a list of token_fragment objects, set a background brush color for all of them. """

    for tf in token_fragments:
      frag = tf.fragment
      fmt = frag.charFormat()
      fmt.setProperty(QtGui.QTextFormat.BackgroundBrush, brush)
      tmpcursor = QtGui.QTextCursor(self.document())
      tmpcursor.setPosition(frag.position())
      tmpcursor.setPosition(frag.position() + frag.length(), QtGui.QTextCursor.KeepAnchor)
      tmpcursor.setCharFormat(fmt)

    return

  def token_color(self, token):
    """ get a color according to token type """

    if type(token) == c.token_global:
      return QtGui.QColor(0x4a,0xa3,0xff,255) # light blue

    if type(token) == c.token_keyword:
      return QtGui.QColor(0x20,0x2d,0xae,255) # dark blue

    if type(token) == c.token_number:
      return QtGui.QColor(0x00,0xac,0x92,255) # blue-green

    if type(token) == c.token_string:
      return QtGui.QColor(0x00,0x70,0x00,255) # dark green

    if type(token) == c.token_var:
      return QtGui.QColor(0x87,0x5b,0x4e,255) # brown

    return QtGui.QColor(0,0,0,255) # black

  def insert_token(self, token):
    """ insert a new token as in the document, with proper formatting. """

    cursor = QtGui.QTextCursor(self.document())
    cursor.movePosition(QtGui.QTextCursor.End)

    brush = QtGui.QBrush(self.token_color(token))
    fmt = QtGui.QTextFormat(QtGui.QTextFormat.CharFormat)
    fmt.setProperty(QtGui.QTextFormat.ForegroundBrush, brush)

    fmt.setProperty(QtGui.QTextFormat.FontStyleHint, QtGui.QFont.Monospace)
    fmt.setProperty(QtGui.QTextFormat.FontWeight, QtGui.QFont.Bold)
    fmt.setProperty(QtGui.QTextFormat.FontFamily, "Liberation Mono")

    fmt.setProperty(QtGui.QTextFormat.UserProperty, token)

    cursor.insertText(str(token), fmt.toCharFormat())

    return

  def update(self, function):

    self.function = function

    t = c.tokenizer(function)
    tokens = list(t.flow_tokens())

    self.clear()

    # insert all tokens as text with proper colors
    self.inserting = True
    for tok in tokens:
      self.insert_token(tok)
    self.inserting = False

    # build a map of which text fragments belong to which token.
    doc = self.document()
    block = doc.begin()
    while block != doc.end():

      for it in block:
        frag = it.fragment()
        fmt = frag.charFormat()
        tok = fmt.property(QtGui.QTextFormat.UserProperty)

        s = str(tok)

        tf = token_fragment(frag, tok)
        if s not in self.__textmap:
            self.__textmap[s] = []
        self.__textmap[s].append(tf)

        self.__fragments.append(tf)

      block = block.next()

    return
