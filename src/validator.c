/**
 * \file
 * \brief Firmware Validator module
 */
#include "validator.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 128

/************************************************
 * PRIVATE METHOD DECLARATION
 ************************************************/
static BIO *read_certificate(const char *cert_name);
static void free_certificate(BIO *certbio);
static X509 *get_certificate_info(BIO *certbio);
static void free_certificate_info(X509 *cert_info);
static EVP_PKEY *get_public_key(X509 *cert_info);
static void free_public_key(EVP_PKEY *pkey);
static int verify_file(const char *file, const char *signature, BIO *certbio);
static char *read_signature(const char *signature, long *length);
static void free_signature_buffer(char *buf);
static long get_file_size(FILE *filp);
static int read_file_to_verify(const char *fname, EVP_MD_CTX *mdctx);

/************************************************
 * PUBLIC METHOD DEFINITION
 ************************************************/

/**
 * \brief Verify firmware file with provided signature and public key
 * \param[in] file filename of a file to verify
 * \param[in] signature_file filename of a file with a secured signature value
 * \param[in] pubkey filename of a certificate the passed @file can be checked with
 */
enum verification_result_t firmware_verify_file(const char *file, 
                                                const char *signature_file, 
                                                const char *certificate)
{
    // add digests as we use digest look up features
    OpenSSL_add_all_digests();

    BIO *certbio = read_certificate(certificate);
    enum verification_result_t retval = FW_INVALID;

    if (certbio != NULL)
    {
        retval = (verify_file(file, signature_file, certbio) == 1) ? FW_VALID : FW_INVALID;
    }
    else
    {
        retval = FW_BAD_CERT;
    }

    free_certificate(certbio);

    return retval;
}

/************************************************
 * PRIVATE METHOD DEFINITION
 ************************************************/

static BIO *read_certificate(const char *cert_name)
{
    BIO *certbio = BIO_new(BIO_s_file());

    if (!certbio)
    {
        printf("Cannot create BIO interface\n");

        return NULL;
    }

    if (BIO_read_filename(certbio, cert_name) != 1)
    {
        printf("Cannot read certificate: %s\n", cert_name);
        BIO_free_all(certbio);

        return NULL;
    }

    return certbio;
}

static void free_certificate(BIO *certbio)
{
    if (certbio != NULL)
    {
        BIO_free_all(certbio);
    }
}

static X509 *get_certificate_info(BIO *certbio)
{
    X509 *cert_info = PEM_read_bio_X509(certbio, NULL, NULL, NULL);

    if (cert_info == NULL)
    {
        printf("Cannot read X509 info from certificate\n");

        return NULL;
    }

    return cert_info;
}

static void free_certificate_info(X509 *cert_info)
{
    if (cert_info != NULL)
    {
        X509_free(cert_info);
    }
}

static EVP_PKEY *get_public_key(X509 *cert_info)
{
    EVP_PKEY *pkey = X509_get_pubkey(cert_info);

    if (pkey == NULL)
    {
        printf("Cannot get public key from X509 certificate\n");

        return NULL;
    }

    return pkey;
}

static void free_public_key(EVP_PKEY *pkey)
{
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }
}

static int verify_file(const char *file, const char *signature, BIO *certbio)
{
    X509 *cert = get_certificate_info(certbio);

    if (cert == NULL)
    {
        return -1;
    }

    EVP_PKEY *pkey = get_public_key(cert);
    int nid = X509_get_signature_nid(cert);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    if (mdctx == NULL)
    {
        printf("Cannot create verificator object\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);

        return -1;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_get_digestbynid(nid), NULL, pkey) != 1)
    {
        printf("Cannot initialize verificator object\n");
        EVP_MD_CTX_destroy(mdctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);

        return -1;
    }

    if (read_file_to_verify(file, mdctx) != 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);

        return -1;
    }

    long sign_size = 0;
    char *sign_buf = read_signature(signature, &sign_size);

    if (sign_buf == NULL)
    {
        EVP_MD_CTX_destroy(mdctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);

        return -1;
    }

    int retval = EVP_DigestVerifyFinal(mdctx, (unsigned char *) sign_buf, sign_size);

    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    free(sign_buf);

    return retval;
}

static char *read_signature(const char *signature, long *length)
{
    if (length == NULL)
    {
        printf("Invalid pointer to length storage\n");

        return NULL;
    }

    FILE *signature_file = fopen(signature, "rb");

    if (signature_file == NULL)
    {
        printf("Cannot open file: %s\n", signature);

        return NULL;
    }

    long file_size = get_file_size(signature_file);

    if (file_size < 0)
    {
        printf("Cannot determine size of file %s\n", signature);
    }
    
    char *buf = calloc(file_size, sizeof(char));
    int read_bytes = 0;
    int offset = 0;

    while ((read_bytes = fread(buf + offset, sizeof(char), file_size, signature_file)) > 0)
    {
        offset += read_bytes;
    }

    if (read_bytes < 0)
    {
        if (feof(signature_file))
        {
            printf("Unexpected EOF\n");
        }
        else if (ferror(signature_file))
        {
            perror("Error reading signature\n");
        }

        free(buf);
        *length = 0;

        return NULL;
    }

    *length = file_size;

    return buf;
}

static void free_signature_buffer(char *buf)
{
    if (buf != NULL)
    {
        free(buf);
    }
}

static long get_file_size(FILE *filp)
{
    if (fseek(filp, 0, SEEK_END) != 0)
    {
        printf("Cannot rewind file\n");

        return -1;
    }

    long file_size = ftell(filp);

    if (file_size == EOF)
    {
        printf("Error during ftell() occured\n");

        return -1;
    }

    rewind(filp);

    return file_size;
}

static int read_file_to_verify(const char *fname, EVP_MD_CTX *mdctx)
{
    FILE *fverif = fopen(fname, "rb");

    if (fverif == NULL)
    {
        printf("Cannot open file %s\n", fname);

        return -1;
    }

    char fbuf[BUFFER_SIZE];

    memset(fbuf, 0, BUFFER_SIZE * sizeof(char));
    int read_bytes = 0;

    while ((read_bytes = fread(fbuf, sizeof(char), BUFFER_SIZE, fverif)) > 0)
    {
        if (EVP_DigestUpdate(mdctx, fbuf, read_bytes) != 1)
        {
            printf("Cannot update verificator object\n");

            return -1;
        }
    }

    if (read_bytes < 0)
    {
        printf("Error during reading of %s occured\n", fname);
    }

    return 0;
}
