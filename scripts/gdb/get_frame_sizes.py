import gdb


class GetFrameSizesCommand(gdb.Command):
    """Gets the size of each frame, and of the whole stack.

    Useful debugging tool to find out which functions have a fat stackframe.
    """

    def __init__(self):
        super(GetFrameSizesCommand, self).__init__(
            "get-frame-sizes",
            gdb.COMMAND_STATUS,
            gdb.COMPLETE_NONE,
            False)

    def invoke(self, args, from_tty):
        frame = gdb.newest_frame()
        frame = frame.older()

        s = 0

        while frame != None:
            newer_frame = frame.newer()

            bottom_esp = newer_frame.read_register("esp")
            top_esp = frame.read_register("esp")
            function_name = frame.function()

            print(str(function_name) + ": " + hex(top_esp - bottom_esp))

            s += top_esp - bottom_esp

            frame = frame.older()

        print("Total stack size: " + hex(s))

GetFrameSizesCommand()