#include <executable/elf.h>
#include <stdio.h>
#include <string.h>

static const uint64_t s_elf_magic = 0x464C457F;
static const char* s_unknown_value = "????";

static const char* ei_osabi_to_str(uint8_t ei_osabi) {
    switch(ei_osabi) {
        case EI_OSABI_System_V:                     return "System V";
        case EI_OSABI_HP_UX:                        return "HP-UX";
        case EI_OSABI_NetBSD:                       return "NetBSD";
        case EI_OSABI_Linux:                        return "Linux";
        case EI_OSABI_GNU_Hurd:                     return "GNU Hurd";
        case EI_OSABI_Solaris:                      return "Solaris";
        case EI_OSABI_AIX:                          return "AIX";
        case EI_OSABI_IRIX:                         return "IRIX";
        case EI_OSABI_FreeBSD:                      return "FreeBSD";
        case EI_OSABI_Tru64:                        return "Tru64";
        case EI_OSABI_Novell_Modesto:               return "Novell Modesto";
        case EI_OSABI_OpenBSD:                      return "OpenBSD";
        case EI_OSABI_OpenVMS:                      return "OpenVMS";
        case EI_OSABI_NonStop_Kernel:               return "NonStop Kernel";
        case EI_OSABI_AROS:                         return "AROS";
        case EI_OSABI_FenixOS:                      return "FenixOS";
        case EI_OSABI_Nuxi_CloudABI:                return "Nuxi CloudABI";
        case EI_OSABI_Stratus_Technologies_OpenVOS: return "Stratus Technologies OpenVOS";
        default:                                    return s_unknown_value;
    }
}

static const char* e_type_to_str(uint16_t e_type) {
    switch(e_type) {
        case ET_NONE:                               return "Unknown";
        case ET_REL:                                return "Relocatable file";
        case ET_EXEC:                               return "Executable file";
        case ET_DYN:                                return "Shared object";
        case ET_CORE:                               return "Core file";
        case ET_LOOS:                           
        case ET_HIOS:                               return "Reserved inclusive range. Operating system specific";
        case ET_LOPROC:                         
        case ET_HIPROX:                             return "Reserved inclusive range. Processor specific";
        default:                                    return s_unknown_value;
    }
}

static const char* e_machine_to_str(uint16_t e_machine) {
    switch (e_machine)
    {
        case E_MACHINE_NO_SPECIFIC:                 return "No specific";
        case E_MACHINE_x86:                         return "x86";
        case E_MACHINE_ARM:                         return "ARM";
        case E_MACHINE_IA_64:                       return "IA-64";
        case E_MACHINE_AMD_x86_64:                  return "x86-64";
        case E_MACHINE_ARM64:                       return "ARM64";
        case E_MACHINE_RISC_V:                      return "RISC-V";
        default:                                    return s_unknown_value;
    }
}

static const char* p_type_to_str(uint32_t p_type) {
    switch(p_type) {
        case PT_NULL:                               return "Entry unused";
        case PT_LOAD:                               return "Loadable segment";
        case PT_DYNAMIC:                            return "Dynamic linking information";
        case PT_INTERP:                             return "Interpreter information";
        case PT_NOTE:                               return "Auxiliary information";
        case PT_SHLIB:                              return "Reserved";
        case PT_PHDR:                               return "Segment containing program header table itself";
        case PT_TLS:                                return "Thread-Local Storage template";
        case PT_LOOS:                       
        case PT_HIOS:                               return "Reserved inclusive range. Operating system specific";
        case PT_LOPROC:                     
        case PT_HIPROC:                             return "Reserved inclusive range. Processor specific";
        default:                                    return s_unknown_value;
    }
}

static const char* sh_type_to_str(uint32_t sh_type) {
    switch(sh_type) {
        case SHT_NULL:                              return "Entry unused";
        case SHT_PROGBITS:                          return "Program data";
        case SHT_SYMTAB:                            return "Symbol table";
        case SHT_STRTAB:                            return "String table";
        case SHT_RELA:                              return "Relocation entries with addends";
        case SHT_HASH:                              return "Symbol hash table";
        case SHT_DYNAMIC:                           return "Dynamic linking information";
        case SHT_NOTE:                              return "Notes";
        case SHT_NOBITS:                            return "Program space with no data (bss)";
        case SHT_REL:                               return "Relocation entries, no addends";
        case SHT_SHLIB:                             return "Reserved";
        case SHT_DYNSYM:                            return "Dynamic linker symbol table";
        case SHT_INIT_ARRAY:                        return "Array of constructors";
        case SHT_FINI_ARRAY:                        return "Array of destructors";
        case SHT_PREINIT_ARRAY:                     return "Array of pre-constructors";
        case SHT_GROUP:                             return "Section group";
        case SHT_SYMTAB_SHNDX:                      return "Extended section indices";
        case SHT_NUM:                               return "Number of defined types.";
        case SHT_LOOS:                              return "Start OS-specific.";
        default:                                    return s_unknown_value;
    }
}

static const char* p_flags_to_str(uint32_t p_flags) {
    static char buff[64];
    buff[0] = '\0';
    
    if (p_flags & PF_R)                             strcat(buff, "READ ");
    if (p_flags & PF_W)                             strcat(buff, "WRITE ");
    if (p_flags & PF_X)                             strcat(buff, "EXECUTE ");

    return buff;
}

static const char* sh_flags_to_str(uint64_t sh_flags) {
    static char buff[512];
    buff[0] = '\0';

    if (sh_flags & SHF_WRITE)                       strcat(buff, "WRITE ");
    if (sh_flags & SHF_ALLOC)                       strcat(buff, "ALLOC ");
    if (sh_flags & SHF_EXECINSTR)                   strcat(buff, "EXEC ");
    if (sh_flags & SHF_MERGE)                       strcat(buff, "MERGE ");
    if (sh_flags & SHF_STRINGS)                     strcat(buff, "STRINGS ");
    if (sh_flags & SHF_INFO_LINK)                   strcat(buff, "INFO_LINK ");
    if (sh_flags & SHF_LINK_ORDER)                  strcat(buff, "LINK_ORDER ");
    if (sh_flags & SHF_OS_NONCONFORMING)            strcat(buff, "OS_NONCONFORMING ");
    if (sh_flags & SHF_GROUP)                       strcat(buff, "GROUP ");
    if (sh_flags & SHF_TLS)                         strcat(buff, "TLS ");
    if (sh_flags & SHF_MASKOS)                      strcat(buff, "MASKOS ");
    if (sh_flags & SHF_MASKPROC)                    strcat(buff, "MASKPROC ");
    if (sh_flags & SHF_ORDERED)                     strcat(buff, "ORDERED ");
    if (sh_flags & SHF_EXCLUDE)                     strcat(buff, "EXCLUDE ");

    return buff;
}

int32_t elf_read(uint8_t* bytes, uint64_t length) {

    struct elf_header* header = (struct elf_header*)bytes;

    
    if(header->e_ident.EI_MAG != s_elf_magic) {
        return ELF_ERROR_INVALID_MAGIC;
    }

    if(header->e_ident.EI_CLASS != EI_CLASS_64_BIT) {
        return ELF_ERROR_UNSUPPORTED_CLASS;
    }

    if(header->e_ident.EI_DATA != EI_DATA_LITTLE_ENDIAN) {
        return ELF_ERROR_UNSUPPORTED_DATA_TYPE;
    }

    printf("------- ELF HEADER -------\n");
    printf("MAGIC: OK\n");
    printf("CLASS: 64 BIT\n");
    printf("DATA TYPE: LITTLE ENDIAN\n");
    printf("ABI: %s\n", ei_osabi_to_str(header->e_ident.EI_OSABI));
    printf("TYPE: %s\n", e_type_to_str(header->e_type));
    printf("MACHINE: %s\n", e_machine_to_str(header->e_machine));
    printf("ENTRY POINT: %#lx\n", header->e_entry);
    printf("PROGRAM HEADER TABLE OFFSET: %#lx\n", header->e_phoff);
    printf("SECTION HEADER TABLE OFFSET: %#lx\n", header->e_shoff);
    printf("FLAGS: %#x\n", header->e_flags);
    printf("HEADER SIZE: %#x\n", header->e_ehsize);
    printf("PROGRAM HEADER TABLE ENTRY SIZE: %#x\n", header->e_phentsize);
    printf("PROGRAM HEADER ENTRY COUNT: %#x\n", header->e_phnum);
    printf("SECTION HEADER TABLE ENTRY SIZE: %#x\n", header->e_shentsize);
    printf("SECTION HEADER ENTRY COUNT: %#x\n", header->e_shnum);
    printf("SECTION NAMES ENTRY IDX: %#x\n", header->e_shstrndx);

    for(uint16_t header_number = 0; header_number < header->e_phnum; header_number++) {
        struct elf_program_header* program_header = (struct elf_program_header*)(bytes + header->e_phoff + sizeof(struct elf_program_header) * header_number);

        printf("\n------- ELF PROGRAM HEADER NO. %#x -------\n", header_number);
        printf("TYPE: %s\n", p_type_to_str(program_header->p_type));
        printf("FLAGS: %s\n", p_flags_to_str(program_header->p_flags));
        printf("SEGMENT OFFSET: %#lx\n", program_header->p_offset);
        printf("SEGMENT VIRT ADDR: %#lx\n", program_header->p_vaddr);
        printf("SEGMENT PHYS ADDR: %#lx\n", program_header->p_paddr);
        printf("SEGMENT SIZE IN IMAGE: %#lx\n", program_header->p_filesz);
        printf("SEGMENT SIZE IN MEMORY: %#lx\n", program_header->p_memsz);
        printf("ALIGN: %#lx\n", program_header->p_align);
    }

    struct elf_section_header* section_names = (struct elf_section_header*)(bytes + header->e_shoff + sizeof(struct elf_section_header) * header->e_shstrndx);
    struct elf_section_header* symtab;
    struct elf_section_header* strtab;

    for(uint16_t section_number = 0; section_number < header->e_shnum; section_number++) {
        struct elf_section_header* section_header = (struct elf_section_header*)(bytes + header->e_shoff + sizeof(struct elf_section_header) * section_number);
        uint8_t* current_name = (uint8_t*)(bytes + section_names->sh_offset + section_header->sh_name);

        printf("\n------- ELF SECTION HEADER NO. %#x -------\n", section_number);
        printf("SECTION NAME: %s\n", current_name);
        printf("TYPE: %s\n", sh_type_to_str(section_header->sh_type));
        printf("FLAGS: %s\n", sh_flags_to_str(section_header->sh_flags));
        printf("SECTION VIRT ADDR: %#lx\n", section_header->sh_addr);
        printf("SECTION OFFSET IN IMAGE: %#lx\n", section_header->sh_offset);
        printf("SECTION SIZE: %#lx\n", section_header->sh_size);
        printf("LINK: %#x\n", section_header->sh_link);
        printf("INFO: %#x\n", section_header->sh_info);
        printf("ALIGN: %#lx\n", section_header->sh_addralign);
        printf("ENTRY SIZE: %#lx\n", section_header->sh_entsize);

        if(strcmp(current_name, ".symtab") == 0) {
            symtab = section_header;
        }
        else if(strcmp(current_name, ".strtab") == 0) {
            strtab = section_header;
        }
    }


    if(symtab == NULL || strtab == NULL) {
        return ELF_OK;
    }

    uint32_t sym_count = symtab->sh_size / sizeof(struct elf_symbol);
    struct elf_symbol* symbols = (struct elf_symbol*)(bytes + symtab->sh_offset);

    uint8_t* symbol_name_base = (uint8_t*)(bytes + strtab->sh_offset);

    printf("\n\n------- DEBUG SYMBOLS -------\n");
    printf("COUNT: %d\n", sym_count);
    for(uint32_t symbol_number = 0; symbol_number < sym_count; symbol_number++) {
        struct elf_symbol* symbol = &symbols[symbol_number];

        printf("[%3d] %016lx %s\n ", symbol_number, symbol->st_value, symbol_name_base + symbol->st_name);
    }

    return ELF_OK;
}