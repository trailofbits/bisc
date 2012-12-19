/*
 * Test a return-oriented payload
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <err.h>

#include <fcntl.h>
#include <sys/stat.h>

void run_rop(unsigned char* rop, size_t rop_size)
{
    uint32_t* return_address_ptr = (uint32_t*)&return_address_ptr + 4;

    if (*return_address_ptr & 0xFFFF0000) {
        errx(EXIT_FAILURE, "Internal error: return address pointer incorrect");
    }
    
    memcpy(return_address_ptr, rop, rop_size);
}

int main(int argc, char* argv[])
{
    int fd, n;
    struct stat stat;
    size_t rop_size;
    unsigned char* rop;
    
    if (argc < 2) {
        errx(EXIT_FAILURE, "usage: %s rop-file.bin", argv[0]);
    }

    if ((fd = open(argv[1], O_RDONLY)) < 0) {
        err(EXIT_FAILURE, "open");
    }

    if (fstat(fd, &stat) < 0) {
        err(EXIT_FAILURE, "fstat");
    }

    rop_size = stat.st_size;
    rop = malloc(rop_size);

    if ((n = read(fd, rop, rop_size)) < 0) {
        err(EXIT_FAILURE, "read");
    }
    else if (n < rop_size) {
        errx(EXIT_FAILURE, "read: short read");
    }

    run_rop(rop, rop_size);
}
