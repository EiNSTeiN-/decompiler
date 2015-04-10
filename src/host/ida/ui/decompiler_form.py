import idautils
import idaapi
import idc

import host
import host.dis
import host.ui

import decompiler

import sys
import traceback

import browser

try:
  import PySide
  from PySide import QtCore, QtGui
except:
  print 'PySide not available'
  raise

sys.modules['__main__'].QtGui = QtGui # goddamit IDA..

decompilation_phase = [
  'Nothing done yet',
  'Basic block information found',
  'Intermediate representation form',
  'Static Single Assignment form',
  'Call information found',
  'Locations renamed',
  'Expressions propagated',
  'Dead code pruned',
  'Decompiled',
]

class DecompilerForm(idaapi.PluginForm):

  def __init__(self, ea):
    idaapi.PluginForm.__init__(self)
    self.ea = ea
    self.__name = idc.Name(self.ea)
    return

  def OnCreate(self, form):
    # Get parent widget
    try:
      self.parent = self.FormToPySideWidget(form, ctx=sys.modules['__main__'])
    except:
      traceback.print_exc()

    self.populate_form()
    return

  def Show(self):
    idaapi.PluginForm.Show(self, self.__name)
    self.decompile()
    return

  def populate_form(self):
    # Create layout
    layout = QtGui.QVBoxLayout()

    self.phase_selection = QtGui.QComboBox(self.parent)
    layout.addWidget(self.phase_selection)
    self.editor = browser.FlowBrowser(self.parent)
    layout.addWidget(self.editor)

    for phase in decompilation_phase:
      self.phase_selection.addItem(phase)

    self.phase_selection.setCurrentIndex(decompiler.STEP_DECOMPILED)
    self.phase_selection.currentIndexChanged.connect(self.phase_selected)

    self.parent.setLayout(layout)

    return

  def phase_selected(self, index):
    self.decompile(index)
    return

  def decompile(self, wanted_step=decompiler.STEP_DECOMPILED):

    dis = host.dis.available_disassemblers['ida'].create()
    d = decompiler.decompiler_t(dis, self.ea)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompilation_phase[step])
      if step >= wanted_step:
        break

    self.editor.update(d.flow)

    return

  def OnClose(self, form):
    pass
