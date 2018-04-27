#include <assert.h>
#include <string.h>

#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto.h"
#include "util.h"

/** Compatibility with older OpenSSL libraries: https://wiki.openssl.org/index.php/Talk:OpenSSL_1.1.0_Changes */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
static HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));
	if (ctx != NULL)
		HMAC_CTX_init(ctx);
	return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx != NULL) {
		HMAC_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}
#endif

/**
 * session_key = HMAC(key, "CBCBE18 Session Key Generation" || nonce_client || nonce_server)
 */
void derive_session_key(const uint8_t *key, size_t keylen,
	const uint8_t *nonce_client, size_t nonce_client_len,
	const uint8_t *nonce_server, size_t nonce_server_len,
	uint8_t *session_key, size_t session_key_length)
{
	HMAC_CTX *ctx = HMAC_CTX_new();
	unsigned int len = SHA256_DIGEST_LENGTH;
	const char *label = "CSCBE18 Session Key Generation";

	hexdump(key, keylen, "[DEBUG] Master key");
	hexdump(nonce_client, nonce_client_len, "[DEBUG] Client nonce");
	hexdump(nonce_server, nonce_server_len, "[DEBUG] Server nonce");

	HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);
	HMAC_Update(ctx, (unsigned char*)label, strlen(label));
	HMAC_Update(ctx, (unsigned char*)nonce_client, nonce_client_len);
	HMAC_Update(ctx, (unsigned char*)nonce_server, nonce_server_len);
	HMAC_Final(ctx, session_key, &len);
	HMAC_CTX_free(ctx);

	hexdump(session_key, session_key_length, "[DEBUG] Session key");
}

/**
 * Calculate Message Authentication Code (MAC) based on key and payload.
 */
void calculate_hmac_sha1(uint8_t *key, size_t keylen, void *payload, size_t payload_len, uint8_t *output, size_t output_len)
{
	HMAC_CTX *ctx = HMAC_CTX_new();
	unsigned int len = SHA_DIGEST_LENGTH;

	assert(output_len == SHA_DIGEST_LENGTH);

	HMAC_Init_ex(ctx, key, keylen, EVP_sha1(), NULL);
	HMAC_Update(ctx, payload, payload_len);
	HMAC_Final(ctx, output, &len);
	HMAC_CTX_free(ctx);
}

/**
 * This function performs both encryption and decryption using a streamcipher (AES in OFB mode)
 */
int crypt_streamcipher(uint8_t *key, size_t keylen, uint8_t *iv, size_t ivlen, 
	uint8_t *in, int inlen, uint8_t *out, int outlen)
{
	assert(keylen == 32);
	assert(ivlen == 16);
	assert(inlen == outlen);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv) != 1)
		return -1;

	if(EVP_DecryptUpdate(ctx, out, &outlen, in, inlen) != 1)
		return -1;

	EVP_CIPHER_CTX_free(ctx);
	return outlen;
}

