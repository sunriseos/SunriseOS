OUTPUT_FORMAT(elf32-i386)
OUTPUT_ARCH(i386)
ENTRY(start)

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC;
  tls PT_TLS;
}

SECTIONS
{
  . = 0;

  /* App code */
  .text : {
    HIDDEN(__text_start__ = .);
    KEEP (*(.text.crt0))
    *(.text .text.*)
    HIDDEN(__text_end__ = .);
  } :text

  /* Trampoline and stuffs */
  .plt : { *(.plt .plt.*) } :text

  /* Read-only sections */
  . = ALIGN(0x1000);

  /* App name */
  .application_name : { KEEP (*(.rodata.application_name)) } :rodata

  /* Make sure everything is aligned */
  . = ALIGN(8);

  /* App rodata */
  .rodata : {
    *(.rodata .rodata.*)
  } :rodata

  /* All the symbols needed for relocation lookup */
  .hash     : { *(.hash) } :rodata
  .gnu.hash : { *(.gnu.hash) } :rodata
  .dynsym   : { *(.dynsym .dynsym.*) } :rodata
  .dynstr   : { *(.dynstr .dynstr.*) } :rodata

  /* All relocations sections */
  .rel.init       : { *(.rel.init) } :rodata
  .rela.init      : { *(.rela.init) } :rodata
  .rel.text       : { *(.rel.text .rel.text.* .rel.gnu.linkonce.t.*) } :rodata
  .rela.text      : { *(.rela.text .rela.text.* .rela.gnu.linkonce.t.*) } :rodata
  .rel.fini       : { *(.rel.fini) } :rodata
  .rela.fini      : { *(.rela.fini) } :rodata
  .rel.rodata     : { *(.rel.rodata .rel.rodata.* .rel.gnu.linkonce.r.*) } :rodata
  .rela.rodata    : { *(.rela.rodata .rela.rodata.* .rela.gnu.linkonce.r.*) } :rodata
  .rel.data       : { *(.rel.data .rel.data.* .rel.gnu.linkonce.d.*) } :rodata
  .rela.data      : { *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*) } :rodata
  .rel.tdata	    : { *(.rel.tdata .rel.tdata.* .rel.gnu.linkonce.td.*) } :rodata
  .rela.tdata	    : { *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*) } :rodata
  .rel.tbss	      : { *(.rel.tbss .rel.tbss.* .rel.gnu.linkonce.tb.*) } :rodata
  .rela.tbss	    : { *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*) } :rodata
  .rel.ctors      : { *(.rel.ctors) } :rodata
  .rela.ctors     : { *(.rela.ctors) } :rodata
  .rel.dtors      : { *(.rel.dtors) } :rodata
  .rela.dtors     : { *(.rela.dtors) } :rodata
  .rel.got        : { *(.rel.got) } :rodata
  .rela.got       : { *(.rela.got) } :rodata
  .rel.bss        : { *(.rel.bss .rel.bss.* .rel.gnu.linkonce.b.*) } :rodata
  .rela.bss       : { *(.rela.bss .rela.bss.* .rela.gnu.linkonce.b.*) } :rodata
  .rel.plt        : { *(.rel.plt) } :rodata
  .rela.plt       : { *(.rela.plt) } :rodata

  /* All exception handling sections */
  .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) } :rodata
  .eh_frame_hdr : {
    __eh_frame_hdr_start__ = .;
    *(.eh_frame_hdr)
    __eh_frame_hdr_end__ = .;
  } :rodata
  .eh_frame : { KEEP (*(.eh_frame)) } :rodata

  /* Misc .rodata stuffs (build-id, ect) */
  .note.gnu.build-id : { *(.note.gnu.build-id) } :rodata

  /* Read-write sections */
  . = ALIGN(0x1000);

  /* App data */
  .data : {
    *(.data .data.*)
  } :data

  /* This section should be made read only after relocation but in practice we will not do that */
  .data.rela.ro : {
    *(.data.rela.ro.local*)
    *(.data.rela.ro .data.rela.ro.*)
  } :data

  /* This section should be made read only after relocation but in practice we will not do that */
  .data.rel.ro : {
    *(.data.rel.ro.local*)
    *(.data.rel.ro .data.rel.ro.*)
  } :data

  /* All GOT sections */
  .got : { *(.got.plt) *(.igot.plt) *(.got) *(.igot) } :data

  /* The dynamic section as we need it to be stored in the binary */
  .dynamic : {
    HIDDEN(__dynamic_start__ = .);
    *(.dynamic)
  } :data :dynamic

  /* Align for .init_array/.fini_array */
  . = ALIGN(8);

  /* App init array */
  .init_array : {
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP (*(.init_array))
  } :data

  /* App fini array */
  .fini_array : {
    KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP (*(.fini_array))
  } :data

  /* Thread Local sections */
  .tdata : {
    *(.tdata .tdata.*)
  } :tls :data

  .tbss : {
    *(.tbss .tbss.*)
    *(.tcommon)
  } :tls :data

  /* Since we don't want our user to have to read its own program headers to find out the size and alignment,
   * we expose symbols so they can be known at runtime */
  __tls_align__ = MAX(ALIGNOF(.tdata), ALIGNOF(.tbss));
  __tls_init_image_addr__ = ADDR(.tdata);
  __tls_file_size__ = SIZEOF(.tdata);
  __tls_mem_size__  = ALIGN(ADDR(.tbss) + SIZEOF(.tbss) - ADDR(.tdata), __tls_align__);

  /* BSS section */
  . = . + SIZEOF(.tbss);
  . = ALIGN(0x1000);

  .bss : {
    HIDDEN(__bss_start__ = .);
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);
    HIDDEN(__bss_end__ = .);
    . = ALIGN(0x1000);
  } :bss

  __argdata__ = .;

  /* Kernel caps and ioports access control */
  .kernel_caps : {
    KEEP(*(.kernel_caps .kernel_caps.*))
  } :NONE

  .kip_header : {
    KEEP(*(.kip_header .kip_header.*))
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

  /DISCARD/ : {
    /* No need of the interpreter */
    *(.interp)

    /* Discard other stuffs */
    *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*)
  }
}
