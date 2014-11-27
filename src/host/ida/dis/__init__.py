import idaapi

import ir
import ir.intel

from . import intel

def find_current_arch():
    """ find the architecture currently in use for this IDB. """
    
    filetype = idaapi.get_file_type_name()
    
    if '386' in filetype:
        print 'Architecture: 32-bit intel.'
        return (ir.IR_INTEL_x86, ir.intel.ir_intel_x86, intel.disassembler)
    elif 'x86-64' in filetype:
        print 'Architecture: 64-bit intel.'
        return (ir.IR_INTEL_x64, ir.intel.ir_intel_x64, intel.disassembler)
    
    raise RuntimeError("Don't know which arch to choose for %s" % (repr(filetype), ))

def disassembler_factory():
    """ Find the correct disassembler module for this host.
    
    Return a new instance of a disassembler made up of the generic 
    architecture support (from arch/*.py) and the specific host disassembler 
    for this architecture.
    """
    
    ir_id, ir_cls, dis_cls = find_current_arch()
    
    class disassembler(dis_cls, ir_cls): # disassembler (host) class must be left-most.
        def __init__(self, ir_id):
            self.ir_id = ir_id
            dis_cls.__init__(self)
            ir_cls.__init__(self)
            return
    
    dis = disassembler(ir_id)
    
    return dis

