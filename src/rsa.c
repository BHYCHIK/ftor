#include "rsa.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static int padding = RSA_PKCS1_PADDING;

static RSA *createRSA(unsigned char *key, int public) {
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL) {
        return NULL;
    }

    if (public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    return rsa;
}

int rsa_public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted, int *error_code) {
    if (error_code) *error_code = 0;
    RSA *rsa = createRSA(key, 1);
    if (!rsa) {
        if (error_code) *error_code = 1;
        return 0;
    }
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int rsa_private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted, int *error_code) {
    if (error_code) *error_code = 0;
    RSA *rsa = createRSA(key, 0);
    if (!rsa) {
        if (error_code) *error_code = 1;
        return 0;
    }
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int rsa_private_encrypt(unsigned char *data, int data_len, unsigned char * key, unsigned char *encrypted, int *error_code) {
    if (error_code) *error_code = 0;
    RSA *rsa = createRSA(key, 0);
    if (!rsa) {
        if (error_code) *error_code = 1;
        return 0;
    }
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int rsa_public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted, int *error_code) {
    if (error_code) *error_code = 0;
    RSA *rsa = createRSA(key, 1);
    if (!rsa) {
        if (error_code) *error_code = 1;
        return 0;
    }
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

//Need at least 130 bytes in buffer
void rsa_get_last_error(char *msg) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), msg);
}
