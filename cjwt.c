#include "cjwt.h"
#include <cstringx.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

unsigned char* base64_decode(const char *input0){
	// 计算输入长度
	size_t input_len = strlen(input0);
	size_t padding=4-(input_len%4);
	char* input=malloc(input_len+padding+1);
	memcpy(input,input0,input_len);
	memset(&input[input_len],'=',padding);
	input_len+=padding;
	input[input_len]=0;
	replaceself(input,'-','+');
	replaceself(input,'_','/');
	// 解码 Base64
	unsigned char* output=malloc(input_len/4*3+padding+1); 
	int output_len = EVP_DecodeBlock(output, (unsigned char *)input, input_len);
	if (output_len == -1) {
		free(input);
		free(output);
		return NULL;
	}
	// 处理填充字符
	if (input_len > 0 && input[input_len - 1] == '=') {
		output_len--;
		if (input_len > 1 && input[input_len - 2] == '=') {
			output_len--;
		}
	}
	free(input);
	// 设置输出长度
	output[output_len]=0;
	output=realloc(output,output_len+1);
	return output;
}
char* base64_encode(const unsigned char *input, size_t input_len){
	char* output=malloc((input_len+2)/3*4+1);
	int output_len=EVP_EncodeBlock((unsigned char *)output, input, input_len);
	output[output_len]=0;
	replaceself((char*)output,'+','-');
	replaceself((char*)output,'/','_');
	replaceself((char*)output,'=',0);
	output=realloc(output,strlen(output)+1);
	return output;
}
void cleanup_openssl() {
	EVP_cleanup();        // 清理算法模块
	// CONF_modules_unload(1); // 卸载配置模块
	CRYPTO_cleanup_all_ex_data(); // 清理扩展数据
	ERR_free_strings();   // 释放错误字符串
	OPENSSL_cleanup();    // OpenSSL 3.0+ 必须
}
char* generate_jwt(const char* header,const char* payload,const char* secret) {
	// Base64 编码 Header
	char* header64=base64_encode((unsigned char *)header, strlen(header));
	// Base64 编码 Payload
	char* payload64=base64_encode((unsigned char *)payload, strlen(payload));
	// 合并
	char* header64_dot_payload64=join(header64,".",payload64);
	free(header64);
	free(payload64);
	// 使用 HMAC-SHA256 签名
	unsigned char* signature=malloc(32);
	HMAC(EVP_sha256(), secret, strlen(secret),(unsigned char*) header64_dot_payload64, strlen((char *)header64_dot_payload64), signature, NULL);
	// Base64 编码签名
	unsigned char* signature64=(unsigned char*)base64_encode((const unsigned char *)signature,32);
	free(signature);
	char* jwt=join(header64_dot_payload64,".",signature64);
	free(header64_dot_payload64);
	free(signature64);
	return jwt;
}
size_t nbase64_decode(size_t input_len){
	return (input_len+3)/4*3;
}
size_t nbase64_encode(size_t input_len){
	return (input_len+2)/3*4;
}
char* md5(const char *input) {
	unsigned char digest[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) return NULL;
	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL)){
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	if (1 != EVP_DigestUpdate(ctx, input, strlen(input))){
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	if (1 != EVP_DigestFinal_ex(ctx, digest, NULL)){
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	EVP_MD_CTX_free(ctx);
	size_t output_len=EVP_MD_size(EVP_md5()) * 2;
	char* output=malloc(output_len+1);
	for (int i = 0; i < EVP_MD_size(EVP_md5()); i++)sprintf(output + (i * 2), "%02x", digest[i]);
	output[output_len] = '\0';
	return output;
}
/*
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