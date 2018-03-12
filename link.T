ENTRY(start)
OUTPUT_FORMAT(elf-i386)

SECTIONS {
	. = 1M;

	.boot ALIGN(4K) : {
		KEEP(*(.multiboot_header))
	}

	.text : {
		*(.text)
	}

	/DISCARD/ : {
		*(.comment*)
		*(.eh_frame*)
		*(.gcc_except_table*)
		*(.note*)
		*(.rel.eh_frame*)
	}
}
