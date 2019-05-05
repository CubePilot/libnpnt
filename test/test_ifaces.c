/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

 /**
 * @file    test/test_ifaces.h
 * @brief   Test libnpnt interfaces
 * @{
 */

// #include <control_iface.h>
// #include <log_iface.h>
// #include <security_iface.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <npnt_internal.h>
#include <jsmn/jsmn.h>
#include <mxml/mxml.h>
#include <npnt.h>
#define ECCTYPE    "secp521r1"

static EC_KEY            *ecckey  = NULL;
static EVP_PKEY          *pkey   = NULL;
static EVP_PKEY          *permart_pkey = NULL;
static BIO               *outbio = NULL;
static int16_t           eccgrp;
static npnt_s            npnt_handle;

int init_ecc_keypair() {
    //These function calls initialize openssl for correct work.
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //Create the Input/Output BIO's.
    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    //Create a EC key sructure, setting the group type from NID
    eccgrp = OBJ_txt2nid("secp521r1");
    ecckey = EC_KEY_new_by_curve_name(eccgrp);

    //For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag
    EC_KEY_set_asn1_flag(ecckey, OPENSSL_EC_NAMED_CURVE);

    //Create the public/private EC key pair here
    if (! (EC_KEY_generate_key(ecckey))) {
        BIO_printf(outbio, "Error generating the ECC key.");
    }

    //Converting the EC key into a PKEY structure let us
    //handle the key just like any other key pair.
    pkey=EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey,ecckey)) {
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
    }

    ecckey = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *ecgrp = EC_KEY_get0_group(ecckey);

    BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
    BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

    //Here we print the private/public key data in PEM format.
    if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL)) {
        BIO_printf(outbio, "Error writing private key data in PEM format");
    }

    if(!PEM_write_bio_PUBKEY(outbio, pkey)) {
        BIO_printf(outbio, "Error writing public key data in PEM format");
    }
    return 0;
}

void free_common() {
    //Free up all structures
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(permart_pkey);
    EC_KEY_free(ecckey);
    BIO_free_all(outbio);
}

int16_t read_and_create_signed_json() {
	FILE *file;
	uint8_t *buffer, *base64_out, *der_sign, *der_sign_base64, *signed_json;
    uint16_t outlen, sig_len, der_sign_base64_len;
	uint32_t fileLen;
    ECDSA_SIG *signature;
    uint8_t hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

	//Open file
	file = fopen("test_art.json", "rb");
	if (!file)
	{
		BIO_printf(outbio, "Unable to open file test_art.json");
		return errno;
	}
	
	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen = ftell(file);
	fseek(file, 0, SEEK_SET);

	//Allocate memory
	buffer = (uint8_t *)malloc(fileLen+1);
	if (!buffer)
	{
		BIO_printf(outbio, "Memory error!");
        fclose(file);
		return errno;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

    base64_out = base64_encode(buffer, fileLen, &outlen);
    free(buffer);
    BIO_printf(outbio, "-----JSON-base64-----\n");
    BIO_printf(outbio, "%s\n", base64_out);

    //Sign JSON
    //Generate SHA256 hash of the data
    SHA256_Update(&sha256, base64_out, outlen);
    SHA256_Final(hash, &sha256);
    signature = ECDSA_do_sign(hash, 32, ecckey);
    if (signature == NULL) {
        BIO_printf(outbio, "Failed to generate EC Signature\n");
        return -1;
    }
    if (ECDSA_do_verify(hash, 32, signature, ecckey) != 1) {
        BIO_printf(outbio, "Failed to verify EC Signature\n");
        return -1;
    } else {
        BIO_printf(outbio, "Verified EC Signature\n");
    }
    // export raw signature to DER-encoded format
    sig_len = i2d_ECDSA_SIG(signature, NULL);
    der_sign = (uint8_t*)malloc(sig_len);
    uint8_t* p = der_sign;
    sig_len= i2d_ECDSA_SIG(signature, &p);
    der_sign_base64 = base64_encode(der_sign, sig_len, &der_sign_base64_len);
    BIO_printf(outbio, "-----Signature-----\n%s\n", der_sign_base64);

    //Create Signed JSON
    const char json_format[] = "{\n\t\"artefact\" : \"%s\",\n\t\"signature\" : \"%s\"\n}\n";
    int16_t signed_json_len = snprintf(NULL, 0, json_format, base64_out, der_sign_base64);
    signed_json = malloc(signed_json_len);
    sprintf((char*)signed_json, json_format, base64_out, der_sign_base64);
    BIO_printf(outbio, "-----Signed-JSON-----\n%s\n", signed_json);

    //Write Data to files for Verification
    FILE* fp = fopen("pubkey.pem", "w");
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    fp = fopen("privkey.pem", "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL);
    fclose(fp);
    // fp = fopen("data.bin", "w");
    // fwrite(base64_out, 1, outlen, fp);
    // fclose(fp);
    // fp = fopen("data_sig.der", "w");
    // fwrite(der_sign, 1, sig_len, fp);
    // fclose(fp);
    fp = fopen("signed_art.json", "w");
    fwrite(signed_json, 1, signed_json_len, fp);
    fclose(fp);

    free(signature);
    free(base64_out);
    free(der_sign_base64);
    free(signed_json);
    return 0;
}

int16_t extract_public_key_from_xml_artefact()
{
    FILE* artefact_xml = fopen("permissionArtifact.xml", "rb");
    int16_t file_len;
    uint8_t *buffer;
    mxml_node_t *permart, *certificate;
    X509 *cert = NULL;
    BIO *cert_bio;

    //Get file length
	fseek(artefact_xml, 0, SEEK_END);
	file_len = ftell(artefact_xml);
	fseek(artefact_xml, 0, SEEK_SET);

    //allocate buffer
	buffer = (uint8_t *)malloc(file_len+1);
	if (!buffer)
	{
		BIO_printf(outbio, "Memory error!");
        fclose(artefact_xml);
		return errno;
	}

	//Read file contents into buffer
	fread(buffer, file_len, 1, artefact_xml);
	fclose(artefact_xml);

    //Extract Certificate from XML
    permart = mxmlLoadString(NULL, buffer, MXML_OPAQUE_CALLBACK);
    if (!permart) {
        BIO_printf(outbio, "Failed to read permission xml\n");
        return -1;
    }

    //Extract Certificate Node
    certificate = mxmlFindElement(permart, permart, "X509Certificate", NULL, NULL, MXML_DESCEND);
    if (!certificate) {
        BIO_printf(outbio, "Failed to extract certificate node\n");
        return -1;
    }

    //Extract Raw Certificate
    mxml_type_t type = mxmlGetType(certificate);    
    const char* cert_der = mxmlGetOpaque(certificate);
    if (!cert_der) {
        BIO_printf(outbio, "Failed to extract raw certificate\n");
        return -1;
    }

    BIO_printf(outbio, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", cert_der);

    //Create Openssl Certificate from raw
    cert_bio = BIO_new(BIO_s_mem());
    BIO_printf(cert_bio, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", cert_der);
    cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    if (!cert) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        return -1;
    }

    permart_pkey = X509_get_pubkey(cert);
    //Extract Public Key
    if (permart_pkey == NULL) {
        BIO_printf(outbio, "Error getting public key from certificate");
        return -1;
    }

    if (EVP_PKEY_RSA == permart_pkey->type) {
        BIO_printf(outbio, "\nFound RSA Key\n");
    } else {
        BIO_printf(outbio, "\nFound non-RSA Key\n");
    }
    PEM_write_bio_PUBKEY(outbio, permart_pkey);
    FILE* pkey_fp = fopen("dgca_pubkey.pem", "w");
    PEM_write_PUBKEY(pkey_fp, permart_pkey);
    fclose(pkey_fp);

    //Free Everything
    free(buffer);
    mxmlDelete(permart);
    BIO_free_all(cert_bio);
    return 0;
}

int16_t load_artifact()
{
    int16_t file_len, outlen;
    uint8_t *buffer = NULL;
    uint8_t *base64_permart = NULL;
    int16_t ret;
    FILE* artefact_xml = fopen("permissionArtifact.xml", "rb");
    //Get file length
	fseek(artefact_xml, 0, SEEK_END);
	file_len = ftell(artefact_xml);
	fseek(artefact_xml, 0, SEEK_SET);

    //allocate buffer
	buffer = (uint8_t *)malloc(file_len+1);
	if (!buffer)
	{
		BIO_printf(outbio, "Memory error!\n");
		ret = errno;
        goto fail;
	}
	//Read file contents into buffer
	fread(buffer, file_len, 1, artefact_xml);

    //convert to base64
    base64_permart = base64_encode(buffer, file_len, &outlen);
    if (!base64_permart) {
        BIO_printf(outbio, "Memory error: Failed to generate base64\n");
        ret = errno;
    }
    BIO_printf(outbio, "XML BASE64:\n%s\n", base64_permart);

    //set artifact
    npnt_init_handle(&npnt_handle);
    ret = npnt_set_permart(&npnt_handle, base64_permart, outlen, true);
    if (ret != 0) {
        BIO_printf(outbio, "Failed to set artifact %d\n", ret);
    } else {
        BIO_printf(outbio, "Artefact Set Successfully!\n", ret);
    }

fail:
	fclose(artefact_xml);
    if (buffer) {
        free(buffer);
    }
    if (base64_permart) {
        free(base64_permart);
    }
    return ret;
}

int main() {
    //Initialise ECC Keypair
    if (init_ecc_keypair() < 0) {
        printf("Failed to Generate ECC Key Pair!\n");
    }

    //Extract Public key from demo XML artifact
    if (extract_public_key_from_xml_artefact() < 0) {
        printf("Failed to extract Public Key from demo XML!\n");
    }

    //Test Loading Artefact
    load_artifact();

    free_common();

    //Test the signed artefact through libnpnt
    return 0;
}

 /** @} */
