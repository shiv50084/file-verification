#include "validator.h"

#include <curl/curl.h>
#include <assert.h>
#include <stdio.h>

static void setup_download_link(CURL *curl, const char *url);
static int download_to_file(CURL *curl, const char *filename);

int main()
{
    CURL *curl = NULL;
    const char *file1_name = "remote_firmware.hex";
    const char *file1_sign = "remote_firmware.hex.sha256";
    const char *cert = "public.pem";

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    if (curl != NULL) {
        // follow redirects
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.54.1");
        setup_download_link(curl, "https://www.dropbox.com/s/47fe3e6yr1aqwqp/firmware.hex?dl=0");
        download_to_file(curl, file1_name);

        setup_download_link(curl, "https://www.dropbox.com/s/0mv9qmij9o13mqb/firmware.hex.sha256?dl=0");
        download_to_file(curl, file1_sign);

        enum verification_result_t is_valid = 
                            firmware_verify_file(file1_name, file1_sign, cert);

        assert(is_valid == FW_VALID);
        // test incorrect file
        is_valid = firmware_verify_file(file1_sign, file1_sign, cert);
        assert(is_valid == FW_INVALID);
        printf("Pass [Remote validation] test\n");

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return 0;
}

static void setup_download_link(CURL *curl, const char *url)
{
    curl_easy_setopt(curl, CURLOPT_URL, url);
}

static int download_to_file(CURL *curl, const char *filename)
{
    FILE *filp = fopen(filename, "wb");
    CURLcode res = 0;

    if (!filp) {
        printf("Cannot open file %s\n", filename);

        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, filp);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    fclose(filp);

    return (res == CURLE_OK) ? 0 : -1;
}
