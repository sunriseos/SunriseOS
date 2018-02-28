ENTRY(start)
OUTPUT_FORMAT(elf64-x86-64)

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
