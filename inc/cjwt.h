#ifndef _CJWT_H
#define _CJWT_H
#include <stddef.h>
void cleanup_openssl();
void base64_decode(unsigned char* output, size_t *output_len,const char *input);
void base64_encode(char *output,const unsigned char *input, size_t input_len);
void hmac_sha256(unsigned char *signature, unsigned int *signature_len, const char *secret, const char *data);
void generate_jwt(char* jwt,const char* header,const char* payload,const char* secret);
void md5(char* output,const char *input);
#endif