""" base class for the intermediate representation.

The IR generation relies on a disassembler to parse the binary object.
Part of the methods below will be provided by the architecture-specific
IR generator, and another part will be provided by the host-specific
disassembler, which the arch-specific code relies upon.
"""

class ir_base(object):

  ## following functions are typically implemented at the IR level. they are used by
  ## the flow code to determine basic blocks in the control flow.

  def is_return(self, ea):
    """ return True if this is a return instruction. """
    raise NotImplemented('base class must override this method')

  def has_jump(self, ea):
    """ return true if this instruction is a jump """
    raise NotImplemented('base class must override this method')

  def next_instruction_ea(self, ea):
    """ return the address of the next instruction. """
    raise NotImplemented('base class must override this method')

  def jump_branches(self, ea):
    """ if this instruction is a jump, yield the destination(s)
        of the jump, of which there may be more than one.

        note that the destination expression is usually a value_t
        representing an address within the function, however it may
        be any other operand type such as a register. """
    raise NotImplemented('base class must override this method')

  def generate_statements(self, ea):
    """ this is where the magic happens, this method yeilds one or more new
    statement corresponding to the given location. """
    raise NotImplemented('base class must override this method')


  ## following functions are typically implemented at the host level. they are used mostly to
  ## translate basic block instructions into the intermediate representation.

  def get_ea_name(self, ea):
    """ return the name of this location, or None if no name is defined. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_string(self, ea):
    """ return the string starting at 'ea' or None if it is not a string. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def function_does_return(self, ea):
    """ return False if the function does not return (ExitThread(), exit(), etc). """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_function_start(self, ea):
    """ return the address of the parent function, given any address inside that function. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_function_items(self, ea):
    """ return all addresses that belong to the function at 'ea'. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_mnemonic(self, ea):
    """ return textual mnemonic for the instruction at 'ea'. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_instruction_size(self, ea):
    """ return the instruction size. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_operand_expression(self, ea, n):
    """ return an expression representing the 'n'-th operand of the instruction at 'ea'. """
    raise NotImplementedException('must be implemented by host-specific disassembler')

  def get_call_expression(self, ea, insn):
    """ get an expression representing a function call at this address. """
    raise NotImplementedException('must be implemented by host-specific disassembler')
