#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <arpa/inet.h>

#include "packets.h"
#include "util.h"
#include "crypto.h"
#include "assert.h"
#include "radium.h"

int radium_read_config(struct radium_session *session, const char *filename)
{
	ssize_t linelen;
	char line[256];
	char *lineptr = line;
	size_t bufsize = sizeof(line);

	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		perror(NULL);
		return -1;
	}

	while ( (linelen = getline(&lineptr, &bufsize, fp)) > 0) {
		// Strip newline
		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		// Parse the config line
		if (strncmp(line, "password=", 9) == 0)
		{
			if (strlen(line + 9) != 6 || !isalphanumeric(line + 9)) {
				goto error;
			}
			strcpy(session->password, line + 9);
		}
		else if (strncmp(line, "secretkey=", 10) == 0)
		{
			if (strlen(line + 10) != 39 || !isprintable(line + 10)) {
				goto error;
			}
			strcpy(session->secretkey, line + 10);
		}
		else if (line[0] != '\0' && line[0] != ';' && line[0] != '#')
		{
			goto error;
		}
	}

	if (errno != 0) {
		perror("");
		goto error;
	}

	fclose(fp);
	return 0;
error:
	fclose(fp);
	return -1;
}

// ====================================================================================
//
//							Packet Transmission Functionality
//
// ====================================================================================

static int send_packet(struct radium_session *session, struct pkt_header *hdr)
{
	hdr->version = RadiumVersion_2;
	hdr->datalen = htons(hdr->datalen);

	if (hdr->encrypted)
	{
		if (!session->using_encryption || !session->handshake_done) {
			fprintf(stderr, "%s: no session key to encrypt packet\n", __FUNCTION__);
			return -1;
		}

		if (os_random(hdr->iv, RADIUM_IV_LEN) < 0) {
			fprintf(stderr, "%s: failed to generate random encryption IV\n", __FUNCTION__);
			return -1;
		}

		if (crypt_streamcipher(session->session_key, RADIUM_SESSION_KEY_LEN, hdr->iv, RADIUM_IV_LEN,
			hdr->data, ntohs(hdr->datalen), hdr->data, ntohs(hdr->datalen)) < 0) {
			fprintf(stderr, "%s: error encryptiong data payload of packet\n", __FUNCTION__);
			return -1;
		}

		calculate_hmac_sha1(session->session_key, RADIUM_SESSION_KEY_LEN, hdr,
			sizeof(*hdr) + ntohs(hdr->datalen), hdr->hmac, RADIUM_HMAC_LEN);
		return write_packet(hdr);
	}
	else
	{
		return write_packet(hdr);
	}
}

static int send_packet_tlvs(struct radium_session *session, enum PacketType msgtype, int encrypted,
	enum TlvType tlvtype1, uint8_t tlvsize1, const uint8_t *tlvdata1,
	enum TlvType tlvtype2, uint8_t tlvsize2, const uint8_t *tlvdata2)
{
	size_t datalen = 2 + tlvsize1 + (tlvdata2 ? 2 + tlvsize2 : 0);
	uint8_t *buffer = malloc(sizeof(struct pkt_header) + datalen);
	struct pkt_header *hdr = (struct pkt_header *)buffer;

	memset(hdr, 0, sizeof(*hdr));
	hdr->msgtype = msgtype;
	hdr->encrypted = encrypted;
	hdr->datalen = datalen;

	uint8_t *data = (uint8_t*)(hdr + 1);
	data[0] = tlvtype1;
	data[1] = tlvsize1;
	memcpy(&data[2], tlvdata1, tlvsize1);

	if (tlvdata2) {
		int pos = 2 + data[1];
		data[pos] = tlvtype2;
		data[pos + 1] = tlvsize2;
		memcpy(&data[pos + 2], tlvdata2, tlvsize2);
	}

	int retval = send_packet(session, hdr);
	free(buffer);
	return retval;
}

#define send_packet_one_tlv(session, msgtype, encrypted, tlvtype, tlvsize, tlvdata) \
	send_packet_tlvs(session, msgtype, encrypted, tlvtype, tlvsize, tlvdata, 0, 0, NULL)
#define send_packet_no_tlvs(session, msgtype) \
	send_packet_tlvs(session, msgtype, 0, 0, 0, NULL, 0, 0, NULL)

static int send_client_hello_secretkey(struct radium_session *session)
{
	if (os_random(session->client_nonce, RADIUM_NONCE_LEN) < 0) {
		fprintf(stderr, "%s: failed to generate random nonce\n", __FUNCTION__);
		return -1;
	}

	return send_packet_one_tlv(session, Packet_ClientHello, 0,
		Tlv_Nonce, RADIUM_NONCE_LEN, session->client_nonce);
}

static int send_client_hello_plaintext(struct radium_session *session)
{
	return send_packet_no_tlvs(session, Packet_ClientHello);
}

static int send_server_hello(struct radium_session *session)
{

	fprintf(stderr, "server hello\n");
	if (session->using_encryption) {
		assert(!is_all_zero(session->server_nonce, RADIUM_NONCE_LEN));
		return send_packet_one_tlv(session, Packet_ServerHello, 0,
			Tlv_Nonce, RADIUM_NONCE_LEN, session->server_nonce);
	} else {
		return send_packet_no_tlvs(session, Packet_ServerHello);
	}
}

static int send_command(struct radium_session *session, const char *command)
{
	if (strlen(command) > 256) {
		fprintf(stderr, "%s: given command too long (%ld characters)\n", __FUNCTION__, strlen(command));
		return -1;
	}

	if (session->password[0] != '\0') {
		return send_packet_tlvs(session, Packet_Command, session->using_encryption,
			Tlv_Command, strlen(command), command,
			Tlv_Password, strlen(session->password), session->password);
	} else {
		return send_packet_one_tlv(session, Packet_Command, session->using_encryption,
			Tlv_Command, strlen(command), command);
	}
}

static int send_output(struct radium_session *session, const char *output)
{
	if (strlen(output) > 256) {
		fprintf(stderr, "%s: output string too large (%ld characters)\n", __FUNCTION__, strlen(output));
		return -1;
	}

	return send_packet_one_tlv(session, Packet_Output, session->using_encryption,
		Tlv_Output, strlen(output), output);
}

// TODO: Define a new packet type for this?
static int send_error(struct radium_session *session, const char *format, ...)
{
	char strerror[256];
	va_list vargs;

	va_start(vargs, format);
	vsnprintf(strerror, sizeof(strerror), format, vargs);
	va_end(vargs);

	return send_packet_one_tlv(session, Packet_Error, 0, Tlv_Error, strlen(strerror), strerror);
}


// ====================================================================================
//
//							Packet Reception Functionality
//
// ====================================================================================

/**
 * Parse the payload and inform misbehaving clients of their idiocity.
 */
static int radium_parse_data(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	uint8_t *data = hdr->data;
	int len = ntohs(hdr->datalen);

	memset(tlvs, 0, sizeof(*tlvs));

	size_t pos = 0;
	while (pos < len && len - pos >= 2)
	{
		// Assure there is enough length for the element
		if (data[pos + 1] > len - pos - 2) {
			send_error(session, "%s: not enough data left for element type %d (need %d bytes but only %d left)\n",
				__FUNCTION__, data[pos], data[pos + 1], len - pos - 2);
			return -1;
		}

		switch (data[pos]) {
		case Tlv_Nonce:
			tlvs->nonce = &data[pos + 2];
			tlvs->nonce_len = data[pos + 1];
			break;
		case Tlv_Password:
			tlvs->password = &data[pos + 2];
			tlvs->password_len = data[pos + 1];
			break;
		case Tlv_Command:
			tlvs->command = &data[pos + 2];
			tlvs->command_len = data[pos + 1];
			break;
		case Tlv_Output:
			tlvs->output = &data[pos + 2];
			tlvs->output_len = data[pos + 1];
			break;
		}

		pos += 2 + data[pos + 1];
	}

	// Assure there is no trailing byte
	if (pos != len) {
		send_error(session, "%s: packet contained %d bytes of trailing data\n", __FUNCTION__, len - pos);
		return -1;
	}

	return 0;
}

static int radium_check_authenticity(struct radium_session *session, struct pkt_header *hdr)
{
	// Nothing to do if no encryption is used, or if it's not an authenticated message
	if (!session->using_encryption || hdr->msgtype < Packet_Command)
		return 0;
	// We need a session key to verify all the other packets
	else if (!session->using_encryption || !session->handshake_done) {
		fprintf(stderr, "%s: no session key available to check authenticity\n", __FUNCTION__);
		return -1;
	}

	// Perform authenticity check based on the session key
	uint8_t received_hmac[RADIUM_HMAC_LEN];
	uint8_t expected_hmac[RADIUM_HMAC_LEN];

	memcpy(received_hmac, hdr->hmac, RADIUM_HMAC_LEN);
	memset(hdr->hmac, 0, RADIUM_HMAC_LEN);
	calculate_hmac_sha1(session->session_key, RADIUM_SESSION_KEY_LEN, hdr, sizeof(*hdr) + ntohs(hdr->datalen), expected_hmac, SHA_DIGEST_LENGTH);
	if (timingsafe_memcmp(received_hmac, expected_hmac, RADIUM_HMAC_LEN) != 0) {
		fprintf(stderr, "%s: received packet with invalid authentication tag\n", __FUNCTION__);
		hexdump(received_hmac, RADIUM_HMAC_LEN, "Received");
		hexdump(expected_hmac, RADIUM_HMAC_LEN, "Expected");
		return -1;
	}

	return 0;
}

static int radium_decrypt_data(struct radium_session *session, struct pkt_header *hdr)
{
	// Nothing to do if not encrypted
	if (!hdr->encrypted)
		return 0;
	// Check if we have a session key
	else if (!session->using_encryption || !session->handshake_done) {
		fprintf(stderr, "%s: received encrypted data but don't have session key to decrypt it\n", __FUNCTION__);
		return -1;
	}

	// Decrypt the data
	if (crypt_streamcipher(session->session_key, RADIUM_SESSION_KEY_LEN, hdr->iv, RADIUM_IV_LEN,
		hdr->data, ntohs(hdr->datalen), hdr->data, ntohs(hdr->datalen)) < 0) {
		fprintf(stderr, "%s: error decrypting data payload of packet\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

static int process_client_hello(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	// By including a nonce, the client requests to use encryption
	if (tlvs->nonce)
	{
		session->using_encryption = 1;

		if (tlvs->nonce_len != RADIUM_NONCE_LEN) {
			send_error(session, "%s: nonce in ClientHello was not %d bytes\n", __FUNCTION__, tlvs->nonce_len);
			return -1;
		}
		memcpy(session->client_nonce, tlvs->nonce, RADIUM_NONCE_LEN);

		if (os_random(session->server_nonce, RADIUM_NONCE_LEN) < 0) {
			fprintf(stderr, "%s: failed to generate server nonce\n", __FUNCTION__);
			return -1;
		}

		derive_session_key(session->secretkey, sizeof(session->secretkey), session->client_nonce, RADIUM_NONCE_LEN,
			session->server_nonce, RADIUM_NONCE_LEN, session->session_key, RADIUM_SESSION_KEY_LEN);
	}

	session->handshake_done = 1;

	return send_server_hello(session);
}

static int process_server_hello(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	// Step 1. Handle encryption if it's used
	if (session->using_encryption)
	{
		// Step 1a: Sanity checks for both secret key negotiation ServerHello
		if (tlvs->nonce == NULL) {
			send_error(session, "%s: server did include a nonce in ServerHello\n", __FUNCTION__);
			return -1;
		} else if (tlvs->nonce_len != RADIUM_NONCE_LEN) {
			send_error(session, "%s: nonce in ServerHello was not %d bytes\n", __FUNCTION__, tlvs->nonce_len);
			return -1;
		}
		memcpy(session->server_nonce, tlvs->nonce, RADIUM_NONCE_LEN);

		// Step 1b: Derive the session key
		derive_session_key(session->secretkey, sizeof(session->secretkey), session->client_nonce, RADIUM_NONCE_LEN,
			session->server_nonce, RADIUM_NONCE_LEN, session->session_key, RADIUM_SESSION_KEY_LEN);
	}

	session->handshake_done = 1;

	// Step 2. For now let the client just execute the single given command
	return send_command(session, session->client_command);
}

static int process_command(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	// Step 1. Sanity check command packet
	if (!session->handshake_done) {
		send_error(session, "%s: received unexpected command packet\n", __FUNCTION__);
		return -1;
	} else if (session->using_encryption && !hdr->encrypted) {
		send_error(session, "%s: received command that was not encrypted\n", __FUNCTION__);
		return -1;
	} else if (tlvs->command == NULL) {
		send_error(session, "%s: command packet did not contain a command string element\n", __FUNCTION__);
		return -1;
	}

	// Step 2. Process supported commands
	if (tlvs->command_len == 4 && timingsafe_memcmp(tlvs->command, "ping", 4) == 0)
	{
		return send_output(session, "pong");
	}
	else if (tlvs->command_len == 8 && timingsafe_memcmp(tlvs->command, "get_flag", 8) == 0)
	{
		// The solution does not involve guessing (i.e. brute-forcing) the password by sending command packets!!
		sleep(1);

		if (tlvs->password == NULL)
			return send_output(session, "Command get_flag requires a valid password");
		else if (tlvs->password_len != strlen(session->password) || timingsafe_memcmp(tlvs->password, session->password, tlvs->password_len) != 0)
			return send_output(session, "Command get_flag requires a valid password");

		return send_output(session, session->secretkey);
	}
	else
	{
		return send_output(session, "Unknown command");
	}
}

static int process_output(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	// Step 1. Sanity check output packet
	if (!session->handshake_done) {
		send_error(session, "%s: received unexpected output packet\n", __FUNCTION__);
		return -1;
	} else if (session->using_encryption && !hdr->encrypted) {
		send_error(session, "%s: received output packet that was not encrypted\n", __FUNCTION__);
		return -1;
	} else if (tlvs->output == NULL) {
		send_error(session, "%s: output packet did not contain an output string element\n", __FUNCTION__);
		return -1;
	}

	// Step 2. Print the output
	fprintf(stderr, "Output: %.*s\n", tlvs->output_len, tlvs->output);

	return 0;
}

static int process_packet(struct radium_session *session, struct pkt_header *hdr)
{
	//
	// Step 1 - General packet processing tasks
	//
	struct radium_tlvs tlvs;

	// Verify version being used
	if (hdr->version != RadiumVersion_2)
		return -1;

	// Verify authenticity of packet if required
	if (radium_check_authenticity(session, hdr) < 0)
		return -1;

	// Decrypt data if required
	if (radium_decrypt_data(session, hdr) < 0)
		return -1;

	// Parse the data into type-length-values if required
	if (radium_parse_data(session, hdr, &tlvs) < 0)
		return -1;


	//
	// Step 2 - Packet processing specific to each message
	//

	if (session->is_server)
	{
		switch (hdr->msgtype) {
		case Packet_ClientHello:
			fprintf(stderr, "process hello\n");
			return process_client_hello(session, hdr, &tlvs);
		case Packet_Command:
			fprintf(stderr, "command :D");
			return process_command(session, hdr, &tlvs);
		default:
			send_error(session, "%s: server received unknown packet type\n", __FUNCTION__);
			return -1;
		}
	}
	else
	{
		switch (hdr->msgtype) {
		case Packet_ServerHello:
			return process_server_hello(session, hdr, &tlvs);
		case Packet_Output:
			return process_output(session, hdr, &tlvs);
		default:
			send_error(session, "%s: client received unknown packet type\n", __FUNCTION__);
			return -1;
		}
	}
}


int radium_loop(struct radium_session *session)
{
	uint8_t buffer[2048];
	struct pkt_header *hdr = (struct pkt_header *)buffer;

	// Client sends the first packet
	if (!session->is_server)
	{
		if (session->using_encryption)
			send_client_hello_secretkey(session);
		else
			send_client_hello_plaintext(session);
	}

	// Now react to received packets
	while (read_packet(buffer, sizeof(buffer)) >= 0)
	{
		if (process_packet(session, hdr) < 0)
			return -1;
	}

	return 0;
}

