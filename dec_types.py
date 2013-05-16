
import idautils
import idc

class regloc_t(object):
    
    regs = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]
    
    def __init__(self, which, index=None):
        self.which = which
        self.index = index
        return
    
    def copy(self):
        return regloc_t(self.which, self.index)
    
    def __eq__(self, other):
        return type(other) == regloc_t and self.which == other.which and \
                self.index == other.index
    
    def __repr__(self):
        name = regloc_t.regs[self.which]
        if self.index is not None:
            name += '@%u' % self.index
        return '<reg %s>' % (name, )
    
    def __str__(self):
        if self.which >= len(regloc_t.regs):
            name = '<#%u>' % (self.which, )
        else:
            name = regloc_t.regs[self.which]
        if self.index is not None:
            name += '@%u' % self.index
        return '%s' % (name, )

class value_t(object):
    """ any literal value """
    def __init__(self, value):
        self.value = value
        return
    
    def copy(self):
        return value_t(self.value)
    
    def __eq__(self, other):
        return type(other) == value_t and self.value == other.value
    
    def __repr__(self):
        return '<value %u>' % self.value
    
    def get_string(self):
        try:
            return idc.GetString(self.value)
        except:
            return
    
    def __str__(self):
        
        if self.value is None:
            return '<none!>'
        
        
        s = self.get_string()
        if s:
            return '%s' % (repr(s), )
        names = dict(idautils.Names())
        if self.value in names:
            return names[self.value]
        
        if self.value < 16:
            return '%u' % self.value
        
        return '0x%x' % self.value

class var_t(object):
    
    def __init__(self, where, name=None):
        self.where = where
        self.name = name or str(self.where)
        return
    
    def copy(self):
        return var_t(self.where.copy(), self.name)
    
    def __eq__(self, other):
        return (type(other) == var_t and self.where == other.where)
    
    def __repr__(self):
        return '<var %s>' % self.name
    
    def __str__(self):
        return self.name

class arg_t(object):
    
    def __init__(self, where, name=None):
        self.where = where
        self.name = name or str(self.where)
        return
    
    def copy(self):
        return arg_t(self.where.copy(), self.name)
    
    def __eq__(self, other):
        return (type(other) == arg_t and self.where == other.where)
    
    def __repr__(self):
        return '<arg %s>' % self.name
    
    def __str__(self):
        return self.name

class expr_t(object):
    
    def __init__(self, *operands):
        self.operands = list(operands)
        return
    
    def __getitem__(self, key):
        return self.operands[key]
    
    def __setitem__(self, key, value):
        self.operands[key] = value

class call_t(expr_t):
    def __init__(self, fct, params):
        expr_t.__init__(self, fct, params)
        return
    
    @property
    def fct(self): return self[0]
    
    @fct.setter
    def fct(self, value): self[0] = value
    
    @property
    def params(self): return self[1]
    
    @params.setter
    def params(self, value): self[1] = value
    
    def __repr__(self):
        return '<call %s %s>' % (repr(self.fct), repr(self.params))
    
    def __str__(self):
        names = dict(idautils.Names())
        if type(self.fct) == value_t:
            name = names.get(self.fct.value, 'sub_%x' % self.fct.value)
        else:
            name = '(%s)' % str(self.fct)
        return '%s(%s)' % (name, str(self.params))
    
    def copy(self):
        return call_t(self.fct.copy(), self.params.copy() if self.params else None)

class uexpr_t(expr_t):
    """ unary expressions, for example --a or a++. """
    
    def __init__(self, operator, op):
        self.operator = operator
        expr_t.__init__(self, op)
        return
    
    @property
    def op(self): return self[0]
    
    @op.setter
    def op(self, value): self[0] = value
    
    def __eq__(self, other):
        return isinstance(other, uexpr_t) and self.operator == other.operator \
            and self.op == other.op
    
    def __repr__(self):
        return '<%s %s %s>' % (self.__class__.__name__, self.operator, repr(self.op))

class bexpr_t(expr_t):
    """ "normal" binary expression. """
    
    def __init__(self, op1, operator, op2):
        self.operator = operator
        expr_t.__init__(self, op1, op2)
        return
    
    @property
    def op1(self): return self[0]
    
    @op1.setter
    def op1(self, value): self[0] = value
    
    @property
    def op2(self): return self[1]
    
    @op2.setter
    def op2(self, value): self[1] = value
    
    def __eq__(self, other):
        return isinstance(other, bexpr_t) and self.operator == other.operator and \
                self.op1 == other.op1 and self.op2 == other.op2
    
    def __repr__(self):
        return '<%s %s %s %s>' % (self.__class__.__name__, repr(self.op1), \
                self.operator, repr(self.op2))

class comma_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, ',', op2)
        return
    
    def __str__(self):
        return '%s, %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return comma_t(self.op1.copy(), self.op2.copy())

class assign_t(bexpr_t):
    """ represent the initialization of a location to a particular expression. """
    
    def __init__(self, op1, op2):
        """ loc: the location being initialized. value: the value it is initialized to. """
        bexpr_t.__init__(self, op1, '=', op2)
        return
    
    def __str__(self):
        return '%s = %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return assign_t(self.op1.copy(), self.op2.copy())

class eq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '==', op2)
        return
    
    def __str__(self):
        return '%s == %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return equals_t(self.op1.copy(), self.op2.copy())

class neq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '!=', op2)
        return
    
    def __str__(self):
        return '%s != %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return not_equals_t(self.op1.copy(), self.op2.copy())

class leq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '<=', op2)
        return
    
    def __str__(self):
        return '%s <= %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return leq_t(self.op1.copy(), self.op2.copy())

class lower_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '<', op2)
        return
    
    def __str__(self):
        return '%s < %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return lower_t(self.op1.copy(), self.op2.copy())

class add_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '+', op2)
        return
    
    def __str__(self):
        return '%s + %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return add_t(self.op1.copy(), self.op2.copy())
    
    def add(self, other):
        if type(other) == value_t:
            self.op2.value += other.value
            return
        
        raise RuntimeError('cannot add %s' % type(other))
    
    def sub(self, other):
        if type(other) == value_t:
            self.op2.value -= other.value
            return
        
        raise RuntimeError('cannot sub %s' % type(other))

class sub_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '-', op2)
        return
    
    def __str__(self):
        return '%s - %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return sub_t(self.op1.copy(), self.op2.copy())
    
    def add(self, other):
        if other.__class__ == value_t:
            self.op2.value -= other.value
            return
        
        raise RuntimeError('cannot add %s' % type(other))
    
    def sub(self, other):
        if other.__class__ == value_t:
            self.op2.value += other.value
            return
        
        raise RuntimeError('cannot sub %s' % type(other))

class mul_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '*', op2)
        return
    
    def __str__(self):
        return '%s * %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return mul_t(self.op1.copy(), self.op2.copy())

class xor_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '^', op2)
        return
    
    def __str__(self):
        return '%s ^ %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return xor_t(self.op1.copy(), self.op2.copy())
    
    def zf(self):
        """ return the expression that sets the value of the zero flag """
        expr = eq_t(self.copy(), value_t(0))
        return expr

class and_t(bexpr_t):
    """ bitwise and (&) operator """
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '&', op2)
        return
    
    def __str__(self):
        return '%s & %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return xor_t(self.op1.copy(), self.op2.copy())

class not_t(uexpr_t):
    """ negate the inner operand. """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '!', op)
        return
    
    def __str__(self):
        return '!(%s)' % (str(self.op), )
    
    def copy(self):
        return deref_t(self.op.copy())

class deref_t(uexpr_t):
    """ indicate dereferencing of a pointer to a memory location. """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '*', op)
        return
    
    def __str__(self):
        return '*(%s)' % (str(self.op), )
    
    def copy(self):
        return deref_t(self.op.copy())

class address_t(uexpr_t):
    """ indicate the address of the given expression (& unary operator). """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '&', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '&%s' % (str(self.op), )
        return '&(%s)' % (str(self.op), )
    
    def copy(self):
        return address_t(self.op)

class condition_t(expr_t):
    """ generic representation of a conditional test """
    pass

class cmp_t(condition_t):
    """ holds two sides of a comparision. """
    
    def __init__(self, op1, op2):
        condition_t.__init__(self, op1, op2)
        return
    
    @property
    def op1(self): return self[0]
    
    @op1.setter
    def op1(self, value): self[0] = value
    
    @property
    def op2(self): return self[1]
    
    @op2.setter
    def op2(self, value): self[1] = value
    
    def __eq__(self, other):
        return type(other) == cmp_t and self.op1 == other.op1 and self.op2 == other.op2
    
    def __repr__(self):
        return '<cmp %s %s>' % (repr(self.op1), repr(self.op2))
    
    def __str__(self):
        return 'cmp %s, %s' % (str(self.op1), str(self.op2))
    
    def zf(self):
        """ return the expression that sets the value of the zero flag """
        expr = eq_t(sub_t(self.op1.copy(), self.op2.copy()), value_t(0))
        return expr

class test_t(condition_t):
    """ represents a "test op1, op2" instruction.
    
    the test sets the zero flag to 1 if a bitwise AND 
    of the two operands results in zero.
    """
    
    def __init__(self, op1, op2):
        condition_t.__init__(self, op1, op2)
        return
    
    @property
    def op1(self): return self[0]
    
    @op1.setter
    def op1(self, value): self[0] = value
    
    @property
    def op2(self): return self[1]
    
    @op2.setter
    def op2(self, value): self[1] = value
    
    def __eq__(self, other):
        return type(other) == cmp_t and self.op1 == other.op1 and self.op2 == other.op2
    
    def __repr__(self):
        return '<test %s %s>' % (repr(self.op1), repr(self.op2))
    
    def __str__(self):
        return 'test %s, %s' % (str(self.op1), str(self.op2))
    
    def zf(self):
        """ return the expression that sets the value of the zero flag """
        expr = eq_t(and_t(self.op1.copy(), self.op2.copy()), value_t(0))
        return expr

class statement_t(object):
    """ defines a statement containing an expression. """
    
    def __init__(self, expr):
        self.expr = expr
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
    
    def __init__(self, _list=None):
        self._list = _list or []
        return
    
    def __repr__(self):
        return repr(self._list)
    
    def __str__(self):
        s = '\n'.join([str(stmt) for stmt in self._list])
        s = '   ' + '\n   '.join(s.split('\n'))
        return s
    
    @property
    def statements(self):
        for item in self._list:
            yield item
            for stmt in item:
                yield stmt
        return
    
    def add(self, stmt):
        assert isinstance(stmt, statement_t), 'cannot add non-statement: %s' % (repr(stmt), )
        self._list.append(stmt)
        return
    
    def __getitem__(self, key):
        #~ print repr(key), repr(self._list)
        return self._list[key]
    
    def __setitem__(self, key, value):
        #~ print 'b', repr(self._list)
        self._list.__setitem__(key, value)
        #~ print 'a', repr(self._list)
        return
    
    def __len__(self):
        return len(self._list)
    
    def extend(self, _new):
        return self._list.extend(_new)
    
    def insert(self, key, _new):
        assert isinstance(_new, statement_t), 'cannot add non-statement: %s' % (repr(stmt), )
        return self._list.insert(key, _new)
    
    def pop(self, key=-1):
        return self._list.pop(key)
    
    def __iter__(self):
        for item in self._list:
            yield item
        return
    
    def remove(self, item):
        if item in self._list:
            return self._list.remove(item)
        else:
            return None

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

class while_t(statement_t):
    """ a while_t statement of the type 'while(expr) { ... }'. """
    
    def __init__(self, expr, container):
        statement_t.__init__(self, expr)
        assert isinstance(container, container_t), '2nd argument to while_t must be container_t'
        self.container = container
        return
    
    def __repr__(self):
        return '<while %s do %s>' % (repr(self.expr), repr(self.container))
    
    def __str__(self):
        c = '\n'.join([str(e) for e in self.container])
        c = '   ' + ('\n   '.join(c.split('\n')))
        s = 'while (%s) {\n%s\n}' % (str(self.expr), c)
        return s

class do_while_t(statement_t):
    """ a do_while_t statement of the type 'do { ... } while(expr)'. """
    
    def __init__(self, expr, container):
        statement_t.__init__(self, expr)
        assert isinstance(container, container_t), '2nd argument to while_t must be container_t'
        self.container = container
        return
    
    def __repr__(self):
        return '<do %s while %s>' % (repr(self.container), repr(self.expr), )
    
    def __str__(self):
        c = '\n'.join([str(e) for e in self.container])
        c = '   ' + ('\n   '.join(c.split('\n')))
        s = 'do {\n%s\n} while (%s)' % (c, str(self.expr))
        return s

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
        return '%s++' % (self.expr, )

class dec_t(statement_t):
    def __init__(self, expr):
        statement_t.__init__(self, expr)
        return
    
    def __repr__(self):
        return '<decrement %s>' % (repr(self.expr) if self.expr else 'void', )
    
    def __str__(self):
        return '%s--' % (self.expr, )

