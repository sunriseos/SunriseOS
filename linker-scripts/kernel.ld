ENTRY(start)
OUTPUT_FORMAT(elf-i386)

PHDRS
{
  text PT_LOAD ;
  data PT_LOAD ;
  dynamic PT_DYNAMIC ;
}

/* The kernel should be mapped in high memory */
KERNEL_OFFSET = 0xc0000000;

SECTIONS {
	/* Keep first page of KernelLand for guard ... */
	. = KERNEL_OFFSET + 0x1000;

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
