""" base class for architectures.

base classes must override the generate_statements method and yield
new statements found at the given location in the database.
"""

class arch_base:
    
    def get_statements(self, block, ea):
        raise NotImplemented('base class must override this method')

