import idautils
import idc

class assignable_t(object):
    """ any object that can be assigned.
    
    They include: regloc_t, var_t, arg_t, deref_t.
    """
    
    def __init__(self):
        self.is_def = False
        return

class regloc_t(assignable_t):
    
    regs = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]
    
    def __init__(self, which, name=None, index=None):
        
        assignable_t.__init__(self)
        
        self.which = which
        self.name = name
        self.index = index
        
        # the is_def flag is set when a register is part of an assign_t on the left side (target of assignment)
        self.is_stackreg = (self.which == 4)
        
        return
    
    def copy(self):
        return self.__class__(self.which, name=self.name, index=self.index)
    
    def __eq__(self, other):
        return type(other) == type(self) and self.which == other.which and \
                self.index == other.index
    
    def __repr__(self):
        if self.name:
            return '<reg %s>' % self.name
        
        name = regloc_t.regs[self.which]
        if self.index is not None:
            name += '@%u' % self.index
        return '<reg %s>' % (name, )
    
    def __str__(self):
        if self.name:
            name = self.name
        elif self.which >= len(regloc_t.regs):
            name = '<#%u>' % (self.which, )
        else:
            name = regloc_t.regs[self.which]
        if self.index is not None:
            name += '@%u' % self.index
        return name
    
    def iteroperands(self):
        yield self
        return

class flagloc_t(regloc_t):
    pass

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
    
    def iteroperands(self):
        yield self
        return

class var_t(assignable_t):
    
    def __init__(self, where, name=None):
        assignable_t.__init__(self)
        
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
    
    def iteroperands(self):
        yield self
        return

class arg_t(assignable_t):
    
    def __init__(self, where, name=None):
        assignable_t.__init__(self)
        
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
    
    def iteroperands(self):
        yield self
        return

class expr_t(object):
    
    def __init__(self, *operands):
        self.__operands = list(operands)
        return
    
    def __getitem__(self, key):
        return self.__operands[key]
    
    def __setitem__(self, key, value):
        self.__operands[key] = value
        return
    
    def __len__(self):
        return len(self.__operands)
    
    def iteroperands(self):
        """ iterate over all operands, depth first, left to right """
        
        for o in self.__operands:
            if not o:
                continue
            for _o in o.iteroperands():
                yield _o
        yield self
        return

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


# #####
# Unary expressions (two operands)
# #####

class uexpr_t(expr_t):
    """ base class for unary expressions """
    
    def __init__(self, operator, op):
        self.operator = operator
        expr_t.__init__(self, op)
        return
    
    def copy(self):
        return self.__class__(self.op)
    
    @property
    def op(self): return self[0]
    
    @op.setter
    def op(self, value): self[0] = value
    
    def __eq__(self, other):
        return isinstance(other, uexpr_t) and self.operator == other.operator \
            and self.op == other.op
    
    def __repr__(self):
        return '<%s %s %s>' % (self.__class__.__name__, self.operator, repr(self.op))

class not_t(uexpr_t):
    """ negate the inner operand. """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '!', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '!%s' % (str(self.op), )
        return '!(%s)' % (str(self.op), )

class deref_t(uexpr_t, assignable_t):
    """ indicate dereferencing of a pointer to a memory location. """
    
    def __init__(self, op):
        assignable_t.__init__(self)
        uexpr_t.__init__(self, '*', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '*%s' % (str(self.op), )
        return '*(%s)' % (str(self.op), )

class address_t(uexpr_t):
    """ indicate the address of the given expression (& unary operator). """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '&', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '&%s' % (str(self.op), )
        return '&(%s)' % (str(self.op), )

class preinc_t(uexpr_t):
    """ pre-increment (++i). """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '++', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '++%s' % (str(self.op), )
        return '++(%s)' % (str(self.op), )

class predec_t(uexpr_t):
    """ pre-decrement (--i). """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '--', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '--%s' % (str(self.op), )
        return '--(%s)' % (str(self.op), )

class postinc_t(uexpr_t):
    """ post-increment (i++). """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '++', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '%s++' % (str(self.op), )
        return '(%s)++' % (str(self.op), )

class postdec_t(uexpr_t):
    """ post-decrement (i--). """
    
    def __init__(self, op):
        uexpr_t.__init__(self, '--', op)
        return
    
    def __str__(self):
        if type(self.op) in (regloc_t, var_t, arg_t, ):
            return '%s--' % (str(self.op), )
        return '(%s)--' % (str(self.op), )


# #####
# Binary expressions (two operands)
# #####

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
        return self.__class__(self.op1.copy(), self.op2.copy())

class assign_t(bexpr_t):
    """ represent the initialization of a location to a particular expression. """
    
    def __init__(self, op1, op2):
        """ op1: the location being initialized. op2: the value it is initialized to. """
        assert isinstance(op1, assignable_t), 'left side of assign_t is not assignable'
        bexpr_t.__init__(self, op1, '=', op2)
        op1.is_def = True
        return
    
    def __setitem__(self, key, value):
        if key == 0:
            assert isinstance(value, assignable_t), 'left side of assign_t is not assignable: %s (to %s)' % (str(value), str(self))
            value.is_def = True
        bexpr_t.__setitem__(self, key, value)
        return
    
    def __str__(self):
        return '%s = %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class add_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '+', op2)
        return
    
    def __str__(self):
        return '%s + %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())
    
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
        return self.__class__(self.op1.copy(), self.op2.copy())
    
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
        return self.__class__(self.op1.copy(), self.op2.copy())

class shl_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '<<', op2)
        return
    
    def __str__(self):
        return '%s << %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class shr_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '>>', op2)
        return
    
    def __str__(self):
        return '%s >> %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class xor_t(bexpr_t):
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '^', op2)
        return
    
    def __str__(self):
        return '%s ^ %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class and_t(bexpr_t):
    """ bitwise and (&) operator """
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '&', op2)
        return
    
    def __str__(self):
        return '%s & %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class or_t(bexpr_t):
    """ bitwise or (|) operator """
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '|', op2)
        return
    
    def __str__(self):
        return '%s | %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

# #####
# Boolean equality/inequality operators
# #####

class b_and_t(bexpr_t):
    """ boolean and (&&) operator """
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '&&', op2)
        return
    
    def __str__(self):
        return '%s && %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class b_or_t(bexpr_t):
    """ boolean and (||) operator """
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '||', op2)
        return
    
    def __str__(self):
        return '%s || %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class eq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '==', op2)
        return
    
    def __str__(self):
        return '%s == %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class neq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '!=', op2)
        return
    
    def __str__(self):
        return '%s != %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class leq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '<=', op2)
        return
    
    def __str__(self):
        return '%s <= %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class aeq_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '>=', op2)
        return
    
    def __str__(self):
        return '%s >= %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class lower_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '<', op2)
        return
    
    def __str__(self):
        return '%s < %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

class above_t(bexpr_t):
    
    def __init__(self, op1, op2):
        bexpr_t.__init__(self, op1, '>', op2)
        return
    
    def __str__(self):
        return '%s > %s' % (str(self.op1), str(self.op2))
    
    def copy(self):
        return self.__class__(self.op1.copy(), self.op2.copy())

# #####
# Special operators that define the value of some of the eflag bits.
# #####

class sign_t(uexpr_t):
    
    def __init__(self, op):
        uexpr_t.__init__(self, '<sign>', op)
        return
    
    def __str__(self):
        return 'SIGN(%s)' % (str(self.op), )

class overflow_t(uexpr_t):
    
    def __init__(self, op):
        uexpr_t.__init__(self, '<overflow>', op)
        return
    
    def __str__(self):
        return 'OVERFLOW(%s)' % (str(self.op), )

class parity_t(uexpr_t):
    
    def __init__(self, op):
        uexpr_t.__init__(self, '<parity>', op)
        return
    
    def __str__(self):
        return 'PARITY(%s)' % (str(self.op), )

class carry_t(uexpr_t):
    
    def __init__(self, op):
        uexpr_t.__init__(self, '<carry>', op)
        return
    
    def __str__(self):
        return 'CARRY(%s)' % (str(self.op), )

