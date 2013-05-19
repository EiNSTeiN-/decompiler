
from expressions import *

class statement_t(object):
    """ defines a statement containing an expression. """
    
    def __init__(self, expr):
        self.expr = expr
        self.container = None
        return
    
    def __repr__(self):
        return '<statement %s>' % (repr(self.expr), )
    
    def __str__(self):
        return '%s;' % (str(self.expr), )
    
    @property
    def statements(self):
        """ by default, no statements are present in this one. """
        return []

class container_t(object):
    """ a container contains statements. """
    
    def __init__(self, __list=None):
        self.__list = __list or []
        for item in self.__list:
            item.container = self
        return
    
    def __repr__(self):
        return repr(self.__list)
    
    def __str__(self):
        s = '\n'.join([str(stmt) for stmt in self.__list])
        s = '   ' + '\n   '.join(s.split('\n'))
        return s
    
    @property
    def statements(self):
        for item in self.__list:
            yield item
        return
    
    def add(self, stmt):
        assert isinstance(stmt, statement_t), 'cannot add non-statement: %s' % (repr(stmt), )
        assert not stmt.container
        self.__list.append(stmt)
        stmt.container = self
        return
    
    def __getitem__(self, key):
        return self.__list[key]
    
    def __setitem__(self, key, value):
        if type(key) == slice:
            for item in value:
                assert isinstance(item, statement_t), 'cannot set non-statement to container'
                item.container = self
        else:
            assert isinstance(value, statement_t), 'cannot set non-statement to container'
            value.container = self
        self.__list.__setitem__(key, value)
        return
    
    def iteritems(self):
        for i in range(len(self.__list)):
            yield i, self.__list[i]
        return
    
    def __len__(self):
        return len(self.__list)
    
    def extend(self, _new):
        for stmt in _new:
            assert isinstance(stmt, statement_t), 'cannot add non-statement to container'
            stmt.container = self
            self.__list.append(stmt)
        return
    
    def insert(self, key, _new):
        assert isinstance(_new, statement_t), 'cannot add non-statement: %s' % (repr(stmt), )
        self.__list.insert(key, _new)
        _new.container = self
        return
    
    def pop(self, key=-1):
        stmt = self.__list.pop(key)
        if stmt:
            stmt.container = None
        return stmt
    
    def index(self, stmt):
        return self.__list.index(stmt)
    
    def __iter__(self):
        for item in self.__list:
            yield item
        return
    
    def remove(self, stmt):
        if stmt in self.__list:
            stmt.container = None
        return self.__list.remove(stmt)
        #~ else:
            #~ return None

class if_t(statement_t):
    """ if_t is a statement containing an expression and a then-side, 
        and optionally an else-side. """
    
    def __init__(self, expr, then):
        statement_t.__init__(self, expr)
        assert isinstance(then, container_t), 'then-side must be container_t'
        self.then_expr = then
        self.else_expr = None
        return
    
    def __repr__(self):
        return '<if %s then %s else %s>' % (repr(self.expr), \
            repr(self.then_expr), repr(self.else_expr))
    
    def __str__(self):
        sthen = '\n'.join([str(e) for e in self.then_expr])
        sthen = '   ' + ('\n   '.join(sthen.split('\n')))
        s = 'if (%s) {\n%s\n}' % (str(self.expr), sthen)
        if self.else_expr:
            selse = '\n'.join([str(e) for e in self.else_expr])
            selse = '   ' + ('\n   '.join(selse.split('\n')))
            s += '\nelse {\n%s\n}' % (selse, )
        return s
    
    @property
    def statements(self):
        for stmt in self.then_expr.statements:
            yield stmt
        if self.else_expr:
            for stmt in self.else_expr.statements:
                yield stmt
        return

class while_t(statement_t):
    """ a while_t statement of the type 'while(expr) { ... }'. """
    
    def __init__(self, expr, loop_container):
        statement_t.__init__(self, expr)
        assert isinstance(loop_container, container_t), '2nd argument to while_t must be container_t'
        self.loop_container = loop_container
        return
    
    def __repr__(self):
        return '<while %s do %s>' % (repr(self.expr), repr(self.loop_container))
    
    def __str__(self):
        c = '\n'.join([str(e) for e in self.loop_container])
        c = '   ' + ('\n   '.join(c.split('\n')))
        s = 'while (%s) {\n%s\n}' % (str(self.expr), c)
        return s
    
    @property
    def statements(self):
        for stmt in self.loop_container:
            yield stmt
        return

class do_while_t(statement_t):
    """ a do_while_t statement of the type 'do { ... } while(expr)'. """
    
    def __init__(self, expr, loop_container):
        statement_t.__init__(self, expr)
        assert isinstance(loop_container, container_t), '2nd argument to while_t must be container_t'
        self.loop_container = loop_container
        return
    
    def __repr__(self):
        return '<do %s while %s>' % (repr(self.loop_container), repr(self.expr), )
    
    def __str__(self):
        c = '\n'.join([str(e) for e in self.loop_container])
        c = '   ' + ('\n   '.join(c.split('\n')))
        s = 'do {\n%s\n} while (%s);' % (c, str(self.expr))
        return s
    
    @property
    def statements(self):
        for stmt in self.loop_container:
            yield stmt
        return

class goto_t(statement_t):
    
    def __init__(self, dst):
        assert type(dst) == value_t
        statement_t.__init__(self, dst)
        return
    
    def __eq__(self, other):
        return type(other) == goto_t and self.expr == other.expr
    
    def __repr__(self):
        s = hex(self.expr.value) if type(self.expr) == value_t else str(self.expr)
        return '<goto %s>' % (s, )
    
    def __str__(self):
        s = ('loc_' + hex(self.expr.value)) if type(self.expr) == value_t else str(self.expr)
        return 'goto %s' % (s, )

class jmpout_t(statement_t):
    """ this is a special case of goto where the address is outside the function. """
    
    def __init__(self, dst):
        assert type(dst) == value_t
        statement_t.__init__(self, dst)
        return
    
    def __eq__(self, other):
        return type(other) == goto_t and self.expr == other.expr
    
    def __repr__(self):
        s = hex(self.expr.value) if type(self.expr) == value_t else str(self.expr)
        return '<jmp out %s>' % (s, )
    
    def __str__(self):
        s = ('loc_' + hex(self.expr.value)) if type(self.expr) == value_t else str(self.expr)
        return 'jump out %s' % (s, )

class return_t(statement_t):
    def __init__(self, expr=None):
        statement_t.__init__(self, expr)
        return
    
    def __repr__(self):
        return '<return %s>' % (repr(self.expr) if self.expr else 'void', )
    
    def __str__(self):
        return 'return %s;' % (str(self.expr) if self.expr else '', )

class inc_t(statement_t):
    def __init__(self, expr):
        statement_t.__init__(self, expr)
        return
    
    def __repr__(self):
        return '<increment %s>' % (repr(self.expr) if self.expr else 'void', )
    
    def __str__(self):
        return '%s++;' % (self.expr, )

class dec_t(statement_t):
    def __init__(self, expr):
        statement_t.__init__(self, expr)
        return
    
    def __repr__(self):
        return '<decrement %s>' % (repr(self.expr) if self.expr else 'void', )
    
    def __str__(self):
        return '%s--;' % (self.expr, )

