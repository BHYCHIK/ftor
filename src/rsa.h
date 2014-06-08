#ifndef __FTOR_RSA_H__
#define __FTOR_RSA_H__

int rsa_public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted, int *error_code);

int rsa_private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted, int *error_code);

int rsa_private_encrypt(unsigned char *data, int data_len, unsigned char * key, unsigned char *encrypted, int *error_code);

int rsa_public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted, int *error_code);

void rsa_get_last_error(char *msg);

void rsa_cleanup();

#endif
