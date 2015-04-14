import idaapi

def show_decompiler():
  import idc

  import host
  import host.ui

  import traceback
  import sys

  import decompiler_form
  reload(decompiler_form)

  try:
    ea = idc.here()
    func = idaapi.get_func(ea)

    ea = func.startEA
    print 'Decompiling %x' % (ea, )

    form = decompiler_form.DecompilerForm(ea)
    form.Show()
  except:
    traceback.print_exc()

  return

def main():
  global hotkey_ctx
  try:
    hotkey_ctx
    if idaapi.del_hotkey(hotkey_ctx):
      print("Hotkey unregistered!")
      del hotkey_ctx
    else:
      print("Failed to delete hotkey!")
  except:
      pass
  hotkey_ctx = idaapi.add_hotkey("F5", show_decompiler)
  if hotkey_ctx is None:
    print("Failed to register hotkey!")
    del hotkey_ctx
  else:
    print("Press F5 to decompile a function.")
