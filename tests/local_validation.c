#include "validator.h"

#include <assert.h>
#include <stdio.h>

int main()
{
    const char *cert = "./public.pem";
    const char *file1_name = "./firmware.hex";
    const char *file1_sign = "./firmware.hex.sha256";
    // test correct file
    enum verification_result_t is_valid = 
                            firmware_verify_file(file1_name, file1_sign, cert);
    
    assert(is_valid == FW_VALID);
    // test incorrect file
    is_valid = firmware_verify_file(file1_sign, file1_sign, cert);
    assert(is_valid == FW_INVALID);
    printf("Pass [Local validation] test\n");

    return 0;
}
