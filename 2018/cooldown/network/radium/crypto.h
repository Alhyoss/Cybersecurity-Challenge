#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

void derive_session_key(const uint8_t *key, size_t keylen,
	const uint8_t *nonce_client, size_t nonce_client_len,
	const uint8_t *nonce_server, size_t nonce_server_len,
	uint8_t *session_key, size_t session_key_length);

void calculate_hmac_sha1(uint8_t *key, size_t keylen, void *payload, size_t payload_len, uint8_t *output, size_t output_len);

int crypt_streamcipher(uint8_t *key, size_t keylen, uint8_t *iv, size_t ivlen, 
	uint8_t *in, int inlen, uint8_t *out, int outlen);

#endif // CRYPTO_H
