""" Browser widget for flow_t object.

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
        
        if self.inserting:
            return
        
        cursor = self.textCursor()
        fmt = cursor.charFormat()
        tok = fmt.property(QtGui.QTextFormat.UserProperty)
        
        if self.__current_highlight:
            brush = QtGui.QBrush(QtGui.QColor(0,0,0,0))
            self.set_fragments_bg(self.__current_highlight, brush)
            self.__current_highlight = None
        
        s = str(tok)
        if s in self.__textmap:
            brush = QtGui.QBrush(QtGui.QColor(0xff,0xff,0x00,200))
            self.set_fragments_bg(self.__textmap[s], brush)
            self.__current_highlight = self.__textmap[s]
        
        #~ print '-> %s' % str(tok)
        
        return
    
    def set_fragments_bg(self, token_fragments, brush):
        
        for tf in token_fragments:
            frag = tf.fragment
            #~ print 'frag %s' % repr(frag.text(), )
            fmt = frag.charFormat()
            fmt.setProperty(QtGui.QTextFormat.BackgroundBrush, brush)
            tmpcursor = QtGui.QTextCursor(self.document())
            #~ print frag.position(), frag.length()
            tmpcursor.setPosition(frag.position())
            tmpcursor.setPosition(frag.position() + frag.length(), QtGui.QTextCursor.KeepAnchor)
            tmpcursor.setCharFormat(fmt)
    
    def token_color(self, token):
        
        if type(token) == c.token_global:
            return QtGui.QColor(0x4a,0xa3,0xff,255)
        
        if type(token) == c.token_keyword:
            return QtGui.QColor(0x20,0x2d,0xae,255)
        
        if type(token) == c.token_number:
            return QtGui.QColor(0x00,0xac,0x92,255)
        
        if type(token) == c.token_string:
            return QtGui.QColor(0x00,0x70,0x00,255)
        
        if type(token) == c.token_var:
            return QtGui.QColor(0x87,0x5b,0x4e,255)
        
        return QtGui.QColor(0,0,0,255)
    
    def set_fragment_format(self, frag, fmt):
        tmpcursor = QtGui.QTextCursor(self.document())
        tmpcursor.setPosition(frag.position())
        tmpcursor.setPosition(frag.position() + frag.length(), QtGui.QTextCursor.KeepAnchor)
        tmpcursor.setCharFormat(fmt)
        return
    
    def insert_token(self, token):
        
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
    
    def update(self, flow):
        
        self.flow = flow
        
        t = c.tokenizer(flow)
        tokens = list(t.flow_tokens())
        
        self.clear()
        
        self.inserting = True
        for tok in tokens:
            self.insert_token(tok)
        self.inserting = False
        
        doc = self.document()
        block = doc.begin()
        while block != doc.end():
            
            for it in block:
                frag = it.fragment()
                fmt = frag.charFormat()
                tok = fmt.property(QtGui.QTextFormat.UserProperty)
                
                s = str(tok)
                print 'inserted %s %s' % (frag.text(), s)
                
                tf = token_fragment(frag, tok)
                if s not in self.__textmap:
                    self.__textmap[s] = []
                self.__textmap[s].append(tf)
                
                self.__fragments.append(tf)
            
            block = block.next()
        
        return
