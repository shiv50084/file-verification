/**
 * \file
 * \brief Firmware Validator module
 */
#include "validator.h"

#include <stdio.h>
#include <stdlib.h>

#define COMMAND_BUF 256
#define OPENSSL_CMD "openssl dgst -sha256 " \
                    "-verify %s -signature %s " \
                    "%s"

/**
 * \brief Verify firmware file with provided signature and public key
 * \param[in] file filename of a file to verify
 * \param[in] signature_file filename of a file with a secured signature value
 * \param[in] pubkey filename of a file with public key that will be used for verifying signature
 */
enum verification_result_t firmware_verify_file(const char *file, 
                                                const char *signature_file, 
                                                const char *pubkey)
{
    char cmd_buf[COMMAND_BUF] = {0};
    int retval = snprintf(cmd_buf, COMMAND_BUF, OPENSSL_CMD, 
                            pubkey, signature_file, file);

    if (retval < 0)
    {
        printf("Error: %d. Cannot printf to buffer\n", retval);

        return FW_BUF_ERR;
    }

    retval = system(cmd_buf);

    return (retval == 0) ? FW_VALID : FW_INVALID;
}
