# zig-dwarfdump

`dwarfdump` utility but in Zig.

### Why?

Turns out the best way of learning a new file/data format is to write a parser yourself, and so here we are.
Perhaps in the future we will be able to use this project as a full substitute for `llvm-dwarfdump`, but time
will tell.

### Usage

```
$ dwarfdump [--help] <FILE>
        --help
            Display this help and exit.
```

### Example usage (MachO)

```
$ dwarfdump main.o

__debug_info contents:
0x0000000000000000: Compile Unit: length = 0x00000000000000a1, format = DWARF32, version = 0x0004, abbr_offset = 0x0000000000000000, addr_size = 0x08 (next unit at 0x00000000000000a5)

0x000000000000000b: DW_TAG_compile_unit
                      DW_AT_producer                          (clang version 15.0.0 (git@github.com:ziglang/zig-bootstrap ae458b715c229ee49397c2c156461ababc7ed98c))
                      DW_AT_language                          (c)
                      DW_AT_name                              (main.c)
                      DW_AT_LLVM_sysroot                      (/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX12.3.sdk)
                      DW_AT_APPLE_sdk                         (MacOSX12.3.sdk)
                      DW_AT_stmt_list                         (0000000000000000)
                      DW_AT_comp_dir                          (/Users/kubkon/dev/zld/examples/hello_c)
                      DW_AT_low_pc                            (0000000000000000)
                      DW_AT_high_pc                           (0000000000000+48)

0x0000000000000032:   DW_TAG_variable
                        DW_AT_type                            (43)
                        DW_AT_decl_file                       (1)
                        DW_AT_decl_line                       (4)
                        DW_AT_location                        ( 3 48 0 0 0 0 0 0 0 )

0x0000000000000043:   DW_TAG_array_type
                        DW_AT_type                            (4f)

0x0000000000000048:     DW_TAG_subrange_type
                          DW_AT_type                          (56)
                          DW_AT_count                         (8)

0x000000000000004e:     NULL

0x000000000000004f:   DW_TAG_base_type
                        DW_AT_name                            (char)
                        DW_AT_encoding                        (6)
                        DW_AT_byte_size                       (1)

0x0000000000000056:   DW_TAG_base_type
                        DW_AT_name                            (__ARRAY_SIZE_TYPE__)
                        DW_AT_byte_size                       (8)
                        DW_AT_encoding                        (7)

0x000000000000005d:   DW_TAG_subprogram
                        DW_AT_low_pc                          (0000000000000000)
                        DW_AT_high_pc                         (0000000000000+48)
                        DW_AT_framebase                       ( 6d )
                        DW_AT_name                            (main)
                        DW_AT_decl_file                       (1)
                        DW_AT_decl_line                       (3)
                        DW_AT_prototyped                      (true)
                        DW_AT_type                            (93)
                        DW_AT_external                        (true)

0x0000000000000076:     DW_TAG_formal_parameter
                          DW_AT_location                      ( 91 78 )
                          DW_AT_name                          (argc)
                          DW_AT_decl_file                     (1)
                          DW_AT_decl_line                     (3)
                          DW_AT_type                          (93)

0x0000000000000084:     DW_TAG_formal_parameter
                          DW_AT_location                      ( 8f 10 )
                          DW_AT_name                          (argv)
                          DW_AT_decl_file                     (1)
                          DW_AT_decl_line                     (3)
                          DW_AT_type                          (9a)

0x0000000000000092:     NULL

0x0000000000000093:   DW_TAG_base_type
                        DW_AT_name                            (int)
                        DW_AT_encoding                        (5)
                        DW_AT_byte_size                       (4)

0x000000000000009a:   DW_TAG_pointer_type
                        DW_AT_type                            (9f)

0x000000000000009f:   DW_TAG_pointer_type
                        DW_AT_type                            (4f)

0x00000000000000a4:   NULL
```

### Building

Remember to clone with submodules, and use latest `zig` master:

```
$ git clone https://github.com/kubkon/zig-dwarfdump.git --recursive
$ zig build
```
