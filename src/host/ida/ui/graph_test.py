import idautils
import idaapi
import idc

import sys

from decompiler import *

class GraphViewer(idaapi.GraphViewer):
  def __init__(self, func):

    self.func = func

    title = "Graph of %x" % (func.startEA, )
    idaapi.GraphViewer.__init__(self, title)

    self.flow = self.decompile()

    self.blkmap = {}
    self.Show()

    return

  def OnGetText(self, id):
    block = self.idmap[id]

    stmts = block.container[:]
    if len(stmts) == 0:
      return ''

    if type(stmts[-1]) == goto_t:
      stmts.pop(-1)

    if type(stmts[-1]) == if_t:
      _if = stmts.pop(-1)
      s = '\n'.join([idaapi.COLSTR(str(stmt), idaapi.SCOLOR_KEYWORD) for stmt in stmts])
      if len(stmts) > 0:
        s += '\n'
      return s + idaapi.COLSTR('if(' + str(_if.expr) + ')', idaapi.SCOLOR_KEYWORD)

    return '\n'.join([idaapi.COLSTR(str(stmt), idaapi.SCOLOR_KEYWORD) for stmt in stmts])

  def OnRefresh(self):
    self.Clear()
    self.idmap = {}
    self.blkmap = {}

    for block in self.flow.iterblocks():
      id = self.AddNode('loc_%x' % block.ea)
      self.idmap[id] = block
      self.blkmap[block] = id

    for block in self.flow.iterblocks():
      src_id = self.blkmap[block]
      for dest in block.jump_to:
        dest_id = self.blkmap[dest]
        self.AddEdge(src_id, dest_id)

    return True

  def decompile(self):

    arch = arch_intel()
    f = flow_t(func.startEA, arch)
    f.prepare_blocks()

    check_stack_alignment(f)

    # tag all registers so that each instance of a register can be uniquely identified.
    # during this process we also take care of matching registers to their respective
    # function calls.
    #~ conv = callconv.stdcall()
    conv = callconv.systemv_x64_abi()
    t = tagger(f, conv)
    t.tag_all()

    #~ print '1'
    # remove special flags (eflags) definitions that are not used, just for clarity
    s = simplifier(f, COLLECT_FLAGS)
    s.remove_unused_definitions()

    #~ print '2'
    # After registers are tagged, we can replace their uses by their definitions. this
    # takes care of eliminating any instances of 'esp' which clears the way for
    # determining stack variables correctly.
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_STACK_LOCATIONS)
    s = simplifier(f, COLLECT_REGISTERS)
    s.remove_unused_definitions()

    #~ print '3'
    # rename stack variables to differenciate them from other dereferences.
    r = renamer(f, RENAME_STACK_LOCATIONS)
    r.wrap_variables()

    # collect function arguments that are passed on the stack
    s = simplifier(f, COLLECT_ALL)
    s.collect_argument_calls(conv)

    #~ print '3.1'
    # This propagates special flags.
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ print '4'
    # At this point we must take care of removing increments and decrements
    # that are in their own statements and "glue" them to an adjacent use of
    # that location.
    s = simplifier(f, COLLECT_ALL)
    s.glue_increments()

    # re-propagate after gluing pre/post increments
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ print '5'
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_ANY | PROPAGATE_SINGLE_USES)

    #~ print '6'
    # eliminate restored registers. during this pass, the simplifier also collects
    # stack variables because registers may be preserved on the stack.
    s = simplifier(f, COLLECT_REGISTERS | COLLECT_VARIABLES)
    s.process_restores()
    # ONLY after processing restores can we do this; any variable which is assigned
    # and never used again is removed as dead code.
    s = simplifier(f, COLLECT_REGISTERS)
    s.remove_unused_definitions()

    #~ print '7'
    # rename registers to pretty names.
    r = renamer(f, RENAME_REGISTERS)
    r.fct_arguments = t.fct_arguments
    r.wrap_variables()

    return f

print 'decompile:', idc.here()
func = idaapi.get_func(idc.here())
g = GraphViewer(func)
