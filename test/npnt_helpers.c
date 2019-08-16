#include <npnt.h>

#ifdef RFM_USE_WOLFSSL
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/pem.h>
#else
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#endif

static SHA256_CTX sha;

void reset_sha256()
{
    SHA256_Init(&sha);
}

void update_sha256(const char* data, uint16_t data_len)
{
    SHA256_Update(&sha, data, data_len);
}

void final_sha256(char* hash)
{
    SHA256_Final((unsigned char*)hash, &sha);
}


#ifdef RFM_USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
static RsaKey         rsaKey;
static RsaKey*        pRsaKey = NULL;
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, uint8_t* signature, uint16_t signature_len)
{
    int ret = 0;

    if (pRsaKey == NULL) {
        /* Initialize the RSA key and decode the DER encoded public key. */
        FILE *fp = fopen("dgca_pubkey.pem", "r");
        if (fp == NULL) {
            return -1;
        }
        fseek(fp, 0L, SEEK_END);
        uint32_t sz = ftell(fp);
        rewind(fp);
        if (sz == 0) {
            return -1;
        }
        uint8_t *filebuf = (uint8_t*)malloc(sz);
        if (filebuf == NULL) {
            return -1;
        }
        uint32_t idx = 0;
        DerBuffer* converted = NULL;

        fread(filebuf, 1, sz, fp);
        ret = wc_PemToDer(filebuf, sz, PUBLICKEY_TYPE, &converted, 0, NULL, NULL);

        if (ret == 0) {
            ret = wc_InitRsaKey(&rsaKey, 0);
        }
        if (ret == 0) {
            ret = wc_RsaPublicKeyDecode(converted->buffer, &idx, &rsaKey, converted->length);
        }
        if (ret == 0) {
            pRsaKey = &rsaKey;
        }
        free(filebuf);
        close(fp);
    }

    if (ret < 0) {
        return -1;
    }
    uint8_t* decSig = NULL;
    uint32_t decSigLen = 0;
    /* Verify the signature by decrypting the value. */
    if (ret == 0) {
        decSigLen = wc_RsaSSL_VerifyInline(signature, signature_len,
                                           &decSig, pRsaKey);
        if ((int)decSigLen < 0) {
            ret = (int)decSigLen;
        }
    }

    /* Check the decrypted result matches the encoded digest. */
    if (ret == 0 && decSigLen != raw_data_len)
        ret = -1;
    if (ret == 0 && XMEMCMP(raw_data, decSig, decSigLen) != 0)
        ret = -1;

    return ret;
}
#else
static EVP_PKEY *dgca_pkey = NULL;
static EVP_PKEY_CTX *dgca_pkey_ctx;
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, const uint8_t* signature, uint16_t signature_len)
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
    if (EVP_PKEY_CTX_set_signature_md(dgca_pkey_ctx, EVP_sha256()) <= 0) {
        ret = -1;
        goto fail;
    }

    /* Perform operation */
    ret = EVP_PKEY_verify(dgca_pkey_ctx, signature, signature_len, raw_data, raw_data_len);

fail:
    EVP_PKEY_CTX_free(dgca_pkey_ctx);
    return ret;
}
#endif
