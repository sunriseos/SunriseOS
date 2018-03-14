ENTRY(start)
OUTPUT_FORMAT(elf-i386)

SECTIONS {
	. = 1M;

	.boot ALIGN(4K) : {
		KEEP(*(.multiboot_header))
	}

	.text : {
		*(.text .text.*)
	}

	.rodata : {
		*(.rodata .rodata.*)
	}

	.data.rel.ro : {
		*(.data.rel.ro.local.*) *(data.rel.ro .data.rel.ro.*)
	}

	/DISCARD/ : {
		*(.comment*)
		*(.eh_frame*)
		*(.gcc_except_table*)
		*(.note*)
		*(.rel.eh_frame*)
	}
}
