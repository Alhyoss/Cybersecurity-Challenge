#ifndef RADIUM_H
#define RADIUM_H

/*
 * ================[             SUMMARY            ]=================
 *
 * A client can connect without encryption, or using secret key (symmetric) encryption. In both cases
 * a ClientHello and ServerHello message is exchanged to initialize the connection. After this phase
 * the client can send commands to the server. Privileged commands require a valid password to execute.
 * Data unique to specific types of packets are saved as type-length-value (TLV) elements.
 *
 *
 * ================[  HANDSHAKE WITHOUT ENCRYPTION  ]================
 *
 *  Client                           Server
 *  ------                           ------
 *    | ------- ClientHello() -------> |      1. Request a plaintext connection
 *    |                                |
 *    | <------ ServerHello() -------- |      2. Accept the plaintext connection
 *
 *
 * ================[    HANDSHAKE WITH ENCRYPTION   ]================
 *
 *
 *  Client                           Server
 *  ------                           ------
 *    | ----- ClientHello(nonce) ----> |      1. Request an encrypted connection. This is indicated by
 *    |                                |         include a random nonce (client_nonce).
 *    |                                |
 *    | <---- ServerHello(nonce) ----- |      2. Accept encrypted connection, and reply with a random
 *    |                                |         nonce (server_nonce).
 *    |                                |
 *    |                                |      Note: the nonces are combined with the shared secret key
 *    |                                |      to derive a fresh session key.
 *    |                                |
 *
 *
 * ================[         EXECUTE COMMAND        ]================
 *
 *  Client                           Server
 *  ------                           ------
 *    | --- Command(cmd[,passwd]) ---> |      1. Send command to the server. Optionally with a password to
 *    |                                |         execute privileged commands.
 *    |                                |
 *    | <----- Output(output) -------- |      2. Reply with the output of the command.
 *    |                                |
 *    |                                |      Note: If encryption is used, data is encrypted using a stream
 *    |                                |      cipher, and the full packet is protected using an authenticity
 *    |                                |      tag. Both crypto operations are based on the fresh session key.
 *    |                                |
 */

#include <openssl/sha.h>

#include "packets.h"

#define RADIUM_SESSION_KEY_LEN		SHA256_DIGEST_LENGTH
#define RADIUM_MASTER_SECRET_LEN	32

struct radium_session {
	// Does this represent a server
	int is_server;
	// If it's a client this is the command that will be executed
	const char *client_command;
	// Symmetric communication key
	char secretkey[40];
	// Pasword for privileged commands
	char password[50];
	// Did the client request the usage of encryption?
	int using_encryption;

	int fd;

	uint8_t client_nonce[RADIUM_NONCE_LEN];
	uint8_t server_nonce[RADIUM_NONCE_LEN];
	uint8_t session_key[RADIUM_SESSION_KEY_LEN];
	uint8_t handshake_done;
};

int radium_read_config(struct radium_session *session, const char *filename);
int radium_loop(struct radium_session *session);

#endif // RADIUM_H
