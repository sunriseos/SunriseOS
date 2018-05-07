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

	.boot : {
		KEEP(*(.multiboot_header))
	} : boot

	. = 0x79C;

	.gdt : {
		*(.gdt)
	}

	. = 1M;

	.stack : {
		*(.stack)
	} : stack

	.text : {
		*(.text .text.*)
	} : text

	.data : {
		*(.data .data.*)
	} : data

	.rodata : {
		*(.rodata .rodata.*)
	} : data

	.got : {
		*(.got)
	} : data

	.bss : {
		*(.bss)
	} : data

	.data.rel.ro : {
		*(.data.rel.ro.local.*) *(data.rel.ro .data.rel.ro.*)
	} : data

	/DISCARD/ : {
		*(.comment*)
		*(.eh_frame*)
		*(.gcc_except_table*)
		*(.note*)
		*(.rel.eh_frame*)
	}
}
