#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <executable/elf.h>

struct format_handler {
    const char* name;
    void (*handler)(uint8_t* buffer, uint64_t length);
};


void handle_elf(uint8_t* buffer, uint64_t length) {
    uint32_t elf_status = elf_read(buffer, length);
    if(elf_status != ELF_OK) {
        printf("ELF ERROR: %#x", elf_status);
    }
}

struct format_handler handlers[1] = {
    { .name = ".elf", .handler = handle_elf }
};





int main(int argc, char* argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage %s <file>\n", argv[0]);
        return 1;
    }
    
    const char *ext = strrchr(argv[1], '.');
    if(!ext || ext == argv[1]) {
        fprintf(stderr, "Unknown file format");
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    
    if(!file) {
        perror("Unable to open file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    uint64_t file_size = ftell(file);
    rewind(file);

    uint8_t* buffer = malloc(file_size);
    if(!buffer) {
        perror("Memory error");
        fclose(file);
        return 1;
    }

    uint64_t bytes_read = fread(buffer, 1, file_size, file);
    if(bytes_read != file_size) {
        perror("Read error");
        fclose(file);
        free(buffer);
        return 1;
    }

    fclose(file);
    
    printf("Read %ld bytes\n", file_size);
    for(uint32_t handler_idx = 0; handler_idx < (sizeof(handlers) / sizeof(struct format_handler)); handler_idx++) {
        if(strcmp(ext, handlers[handler_idx].name) == 0) {
            printf("Using handler for format: %s\n", handlers[handler_idx].name);
            handlers[handler_idx].handler(buffer, file_size);
            free(buffer);
            return 0;
        }
    }

    free(buffer);
    fprintf(stderr, "File format: %s is not supported\n", ext);
    return 1;
}

