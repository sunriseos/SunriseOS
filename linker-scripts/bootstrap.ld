ENTRY(bootstrap_start)
OUTPUT_FORMAT(elf32-i386)

PHDRS
{
  boot PT_LOAD ;
  gdt  PT_LOAD ;
  text PT_LOAD ;
  rodata PT_LOAD ;
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

	.text ALIGN(4K) : {
		*(.text .text.*)
	} : text

	.rodata ALIGN(4K) : {
		*(.rodata .rodata.*)
	} : rodata

	.data ALIGN(4K) : {
		*(.data .data.*)
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
