#include <npnt.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

static SHA_CTX sha;

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