ENTRY(start)
OUTPUT_FORMAT(elf-i386)

SECTIONS {
	. = 0;

	.boot ALIGN(4K) : {
		KEEP(*(.multiboot_header))
	}

	. = 0x79C;

	.gdt : {
		*(.gdt)
	}

	. = 1M;


	.text : {
		*(.text .text.*)
	}

	.data : {
		*(.data .data.*)
	}

	.rodata : {
		*(.rodata .rodata.*)
	}

	.got : {
		*(.got)
	}

	.bss : {
		*(.bss)
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
