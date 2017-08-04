#include "validator.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define RSA4096_SIZE 512

char *read_signbuf(const char *sign_filename, long *length);

int main()
{
    const char *cert = "./public.pem";
    const char *file1_name = "./firmware.hex";
    const char *file1_sign = "./firmware.hex.sha256";
    long length = 0;
    char *sign_buf = read_signbuf(file1_sign, &length);
    // test correct file
    enum verification_result_t is_valid = 
                            firmware_verify_file_sign_buf(file1_name, sign_buf, length, cert);
    
    assert(sign_buf);
    assert(is_valid == FW_VALID);
    // test incorrect file
    is_valid = firmware_verify_file(file1_sign, file1_sign, cert);
    assert(is_valid == FW_INVALID);
    printf("Pass [Local validation with external signature buffer] test\n");

    return 0;
}

char *read_signbuf(const char *sign_filename, long *length)
{
    if (!length)
    {
        return NULL;
    }

    FILE *filp = fopen(sign_filename, "rb");

    if (!filp)
    {
        printf("Cannot open %s\n", sign_filename);

        return NULL;
    }

    char *buf = calloc(RSA4096_SIZE, sizeof(char));
    int read_bytes = 0;
    int offset = 0;

    while ((read_bytes = fread(buf + offset, sizeof *buf, RSA4096_SIZE, filp)) > 0)
    {
        offset += read_bytes;
    }

    if (read_bytes < 0)
    {
        printf("Error during reading\n");
        free(buf);

        return NULL;
    }

    *length = offset;

    return buf;
}