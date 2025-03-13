#include <cjwt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void md5(char* output,const char *input) {
	unsigned char digest[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) return;
	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL)){
		ERR_print_errors_fp(stderr);
		return;
	}
	if (1 != EVP_DigestUpdate(ctx, input, strlen(input))){
		ERR_print_errors_fp(stderr);
		return;
	}
	if (1 != EVP_DigestFinal_ex(ctx, digest, NULL)){
		ERR_print_errors_fp(stderr);
		return;
	}
	EVP_MD_CTX_free(ctx);
	for (int i = 0; i < EVP_MD_size(EVP_md5()); i++)sprintf(output + (i * 2), "%02x", digest[i]);
	output[EVP_MD_size(EVP_md5()) * 2] = '\0';
}
// Base64 解码函数
void base64_decode(unsigned char* output, size_t *output_len,const char *input) {
	// 计算输入长度
	size_t input_len = strlen(input);
	size_t padding=4-(input_len%4);
	char* inputx=malloc(input_len+padding+1);
	memcpy(inputx,input,input_len);
	memset(&inputx[input_len],'=',padding);
	input_len+=padding;
	inputx[input_len]=0;
	for(size_t i=0;i<input_len;i++){
		if(inputx[i]=='-')inputx[i]='+';
		if(inputx[i]=='_')inputx[i]='/';
	}
	// 解码 Base64
	int decoded_len = EVP_DecodeBlock(output, (unsigned char *)inputx, input_len);
	if (decoded_len == -1) {
		free(inputx);
		*output_len=0;
		return;
	}
	// 处理填充字符
	if (input_len > 0 && inputx[input_len - 1] == '=') {
		decoded_len--;
		if (input_len > 1 && inputx[input_len - 2] == '=') {
			decoded_len--;
		}
	}
	free(inputx);
	// 设置输出长度
	*output_len = decoded_len;
	output[*output_len]=0;
	return;
}

// Base64 编码函数
void base64_encode(char *output,const unsigned char *input, size_t input_len) {
	int encoded_len=EVP_EncodeBlock((unsigned char *)output, input, input_len);
	output[encoded_len]=0;
	char* p=output;
	while(*p){
		if(*p=='/')*p='_';
		else if(*p=='+')*p='-';
		else if(*p=='=')*p=0;
		p++;
	}
}

// HMAC-SHA256 签名函数
// unsigned char *hmac_sha256(const char *secret, const char *data, unsigned int *result_len) {
// 	return HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char *)data, strlen(data), NULL, result_len);
// }
void hmac_sha256(unsigned char *signature, unsigned int *signature_len, const char *secret, const char *data) {
	HMAC(EVP_sha256(),
		 secret,
		 (int)strlen(secret),
		 (const unsigned char *)data,
		 (int)strlen(data),
		 (unsigned char *)signature,
		 signature_len);
	signature[*signature_len]=0;
}
// 生成 JWT
void generate_jwt(char* jwt,const char* header,const char* payload,const char* secret) {
	// Base64 编码 Header
	char *p=jwt;
	base64_encode(p,(unsigned char *)header, strlen(header));
	size_t n=strlen(p);
	p+=n;
	*p='.';
	// Base64 编码 Payload
	p++;
	base64_encode(p,(unsigned char *)payload, strlen(payload));
	n=strlen(p);
	p+=n;
	*p=0;
	// *p='.';
	// p++;
	// 使用 HMAC-SHA256 签名
	unsigned int signature_len;
	hmac_sha256((unsigned char*)&p[500], &signature_len,secret, jwt);
	*p='.';
	p++;
	// Base64 编码签名
	base64_encode(p,(unsigned char*)&p[499], signature_len);
}
void cleanup_openssl() {
	EVP_cleanup();        // 清理算法模块
	// CONF_modules_unload(1); // 卸载配置模块
	CRYPTO_cleanup_all_ex_data(); // 清理扩展数据
	ERR_free_strings();   // 释放错误字符串
	OPENSSL_cleanup();    // OpenSSL 3.0+ 必须
}/*
int main1() {
	// JWT Header 和 Payload
	const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	const char *payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";

	// 密钥
	const char *secret = "your-256-bit-secret";

	// 生成 JWT
	char jwt[0x1000];
	// memset((char*)jwt,0,0x1000);
	// printf("%p\n",&jwt);
	generate_jwt((char*)jwt,header, payload, secret);
	printf("Generated JWT: %s\n", jwt);
	return 0;
}*/