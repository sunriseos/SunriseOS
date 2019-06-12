### Content

This folder contains gdb scripts and configurations, to help you keep your sanity during debugging sessions.

##### gdbinit

This template gdbinit is provided as an example. 

You shouldn't use or modify it directly, but rather copy it to the root of this project, where it will be ignored by git and make any modifications you want there. 
That way everyone can keep their own custom version without being harassed by git.

For it to be used by gdb when you start it, make sure to add this line to your `~/.gdbinit`:

```shell
$ cat ~/.gdbinit
#authorize running the .gdbinit in some folders
add-auto-load-safe-path <path to sunrise>/.gdbinit
```
