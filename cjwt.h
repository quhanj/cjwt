#ifndef _CJWT_H
#define _CJWT_H
#include <stddef.h>

unsigned char* base64_decode(const char *input);
char* base64_encode(const unsigned char *input, size_t input_len);
void cleanup_openssl();
char* generate_jwt(const char* header,const char* payload,const char* secret);
unsigned char* hmac_sha256(const char *secret, const char *data);
size_t nbase64_decode(size_t input_len);
size_t nbase64_encode(size_t input_len);
char* md5(const char *input);
#endif