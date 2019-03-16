#include <npnt.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

static SHA_CTX sha;
static EVP_PKEY *dgca_pkey = NULL;
static EVP_PKEY_CTX *dgca_pkey_ctx;

void reset_sha1()
{
    SHA1_Init(&sha);
}

void update_sha1(const char* data, uint16_t data_len)
{
    SHA1_Update(&sha, data, data_len);
}

void final_sha1(char* hash)
{
    SHA1_Final((unsigned char*)hash, &sha);
}

int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, uint8_t* signature, uint16_t signature_len)
{
    if (!handle || !raw_data || !signature) {
        return -1;
    }
    if (dgca_pkey == NULL) {
        FILE *fp = fopen("dgca_pubkey.pem", "r");
        if (fp == NULL) {
            return -1;
        }
        dgca_pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }
    dgca_pkey_ctx = EVP_PKEY_CTX_new(dgca_pkey, ENGINE_get_default_RSA());
    if (!dgca_pkey_ctx) {
        return -1;
    }
    int ret = 0;
    if (EVP_PKEY_verify_init(dgca_pkey_ctx) <= 0) {
        ret = -1;
        goto fail;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(dgca_pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
        ret = -1;
        goto fail;
    }

    /* Perform operation */
    ret = EVP_PKEY_verify(dgca_pkey_ctx, signature, signature_len, raw_data, raw_data_len);

fail:
    EVP_PKEY_CTX_free(dgca_pkey_ctx);
    return ret;
}