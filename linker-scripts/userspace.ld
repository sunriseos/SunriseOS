ENTRY(start)
OUTPUT_FORMAT(elf32-i386)

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC;
}

SECTIONS
{
  . = 0;

  .text : ALIGN(0x1000) {
    KEEP(*(.text.crt0))
    *(.text.unlikely .text.*_unlikely .text.unlikely.*)
    *(.text.exit .text.exit.*)
    *(.text.startup .text.startup.*)
    *(.text.hot .text.hot.*)
    *(.text .stub .text.* .gnu.linkonce.t.*)
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
  }

  /* RO sections */

  . = ALIGN(0x1000);

  .rodata : { *(.rodata .rodata.*) } :rodata
  .hash : { *(.hash) }
  .dynsym : { *(.dynsym .dynsym.*) }
  .dynstr : { *(.dynstr .dynstr.*) }
  .rela.dyn : { *(.rela.dyn) } :rodata
  .rela.plt : { *(.rela.plt) } :rodata

  .eh_frame : ONLY_IF_RO {
    HIDDEN(__eh_frame_start = .);
    *(.eh_frame .eh_frame.*)
    HIDDEN(__eh_frame_end = .);
  }

  .eh_frame_hdr : {
    EH_FRAME_HDR_START = .;
    *(.eh_frame_hdr .eh_frame_hdr.*)
    EH_FRAME_HDR_END = .;
  }

  .gcc_except_table : ONLY_IF_RO { *(.gcc_except_table .gcc_except_table.*) }
  .gnu_extab : ONLY_IF_RO { *(.gnu_extab*) }

  .dynamic : {
    DYNAMIC = .;
    *(.dynamic)
  } :rodata :dynamic

  /* RW sections */

  . = ALIGN(0x1000);
  .data : {
    *(.data .data.*)
    *(.got .got.*)
    *(.got.plt .got.plt.*)
  } :data

  .eh_frame : ONLY_IF_RW {
    HIDDEN(__eh_frame_start = .);
    KEEP (*(.eh_frame)) *(.eh_frame.*)
    HIDDEN(__eh_frame_end = .);
  }
  .gnu_extab : ONLY_IF_RW { *(.gnu_extab*) }
  .gcc_except_table : ONLY_IF_RW { *(.gcc_except_table .gcc_except_table.*) }

  /* BSS section */

  . = ALIGN(0x1000);

  .bss : {
   BSS_START = .;
   *(.dynbss)
   *(.bss .bss.* .gnu.linkonce.b.*)
   *(COMMON)
   /* Align here to ensure that the .bss section occupies space up to
      _end.  Align after .bss to ensure correct alignment even if the
      .bss section disappears because there are no input sections.
      FIXME: Why do we need it? When there is no .bss section, we don't
      pad the .data section.  */
   . = ALIGN(. != 0 ? 64 / 8 : 1);
   BSS_END = .;
  } :bss

  /* Kernel caps and ioports access control */
  .kernel_caps : {
    KEEP(*(.kernel_caps .kernel_caps.*))
  } :NONE

  .kernel_ioports : {
    KEEP(*(.kernel_ioports .kernel_ioports.*))
  } :NONE

  /* Stabs debugging sections.  */
  .stab          0 : { *(.stab) }
  .stabstr       0 : { *(.stabstr) }
  .stab.excl     0 : { *(.stab.excl) }
  .stab.exclstr  0 : { *(.stab.exclstr) }
  .stab.index    0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment       0 : { *(.comment) }
  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section so we begin them at 0.  */
  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line .debug_line.* .debug_line_end ) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }
  /* DWARF 3 */
  .debug_pubtypes 0 : { *(.debug_pubtypes) }
  .debug_ranges   0 : { *(.debug_ranges) }
  /* DWARF Extension.  */
  .debug_macro    0 : { *(.debug_macro) }
  .debug_addr     0 : { *(.debug_addr) }
  .gnu.attributes 0 : { KEEP (*(.gnu.attributes)) }
  /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }
}
