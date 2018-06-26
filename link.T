ENTRY(start)
OUTPUT_FORMAT(elf-i386)

PHDRS
{
  boot PT_LOAD ;
  gdt  PT_LOAD ;
  stack PT_LOAD ;
  text PT_LOAD ;
  data PT_LOAD ;
  dynamic PT_DYNAMIC ;
}

SECTIONS {
	. = 0;

	.boot ALIGN(4K) : {
		KEEP(*(.multiboot_header))
	} : boot

	.gdt ALIGN(4K) : {
		*(.gdt)
	}

	. = 1M;

	.stack ALIGN(4K) : {
		*(.stack)
	} : stack

	.text ALIGN(4K) : {
		*(.text .text.*)
	} : text

	.data ALIGN(4K) : {
		*(.data .data.*)
	} : data

	.rodata ALIGN(4K) : {
		*(.rodata .rodata.*)
	} : data

	.got ALIGN(4K) : {
		*(.got)
	} : data

	.bss ALIGN(4K) : {
		BSS_START = .;
		*(.bss)
		BSS_END = .;
	} : data

	.data.rel.ro ALIGN(4K) : {
		*(.data.rel.ro.local.*) *(data.rel.ro .data.rel.ro.*)
	    . = ALIGN(4K);
	} : data

	/DISCARD/ : {
		*(.comment*)
		*(.eh_frame*)
		*(.gcc_except_table*)
		*(.note*)
		*(.rel.eh_frame*)
	}
}
