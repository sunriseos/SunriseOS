import gdb

class UserspaceBreakpoint(gdb.Breakpoint):
	"""Breakpoint breaking only in the right sunrise executable

Breakpoint that breaks only if we're in the right userspace executable, since all .text are loaded at the same address.

It uses the name found in the kernel current ProcessStruct and compares it with the module we're debugging to decide if it should break or not.
	"""
	def __init__(self, *args, **kwargs):
		super(UserspaceBreakpoint, self).__init__(*args, **kwargs)
		for objfile in gdb.objfiles():
			filename = objfile.filename.split("/")[-1]
			if not filename.startswith("sunrise-kernel"):
				self.proc_name = filename.split("sunrise-")[-1]
				break


	def stop (self):
		cur_proc_name_expr = "(*sunrise_kernel::scheduler::CURRENT_THREAD.0.ptr.pointer).data.process.ptr.pointer.data.name.vec.buf.ptr.pointer"
		cur_proc_name = gdb.parse_and_eval(cur_proc_name_expr).string()
		if cur_proc_name == self.proc_name:
			return True
		return False

class BreakUserspaceCommand(gdb.Command):
	"""Break only if in the right sunrise executable

Creates a breakpoint that breaks only if we're in the right userspace executable, since all .text are loaded at the same address.

It uses the name found in the kernel current ProcessStruct and compares it with the module we're debugging to decide if it should break or not.

Usage: 
	break_userspace { args forwarded to break }
	"""
	def __init__(self):
		super(BreakUserspaceCommand, self).__init__(
				"break_userspace",
				gdb.COMMAND_BREAKPOINTS,
				gdb.COMPLETE_LOCATION,
				False)

	def invoke(self, args, from_tty):
		UserspaceBreakpoint(args)

BreakUserspaceCommand()
