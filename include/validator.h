/**
 * \file
 * \brief Firmware Validator module
 */
#ifndef _FIRMWARE_VALIDATOR_H_
#define _FIRMWARE_VALIDATOR_H_

#include <stdbool.h>

enum verification_result_t { FW_BUF_ERR, FW_VALID, FW_INVALID, FW_BAD_CERT };

enum verification_result_t firmware_verify_file(const char *file,
                                                const char *signature_file,
                                                const char *certificate);

enum verification_result_t firmware_verify_file_sign_buf(
    const char *file, const char *signature, long length,
    const char *certificate);

#endif /* _FIRMWARE_VALIDATOR_H_ */
