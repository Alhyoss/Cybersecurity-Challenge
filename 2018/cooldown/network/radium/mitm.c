#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include <stdint.h>

#include <arpa/inet.h>

#include "radium.h"
#include "crypto.h"
#include "util.h"

static ssize_t recv_len_m(int fd, void *packet, size_t n)
{
	uint8_t *buf = (uint8_t*)packet;
	ssize_t rc;
	size_t pos = 0;
	while (pos < n)
	{
		rc = read(fd, buf + pos, n - pos);
		if (rc == -1) {
		    if (errno == EAGAIN || errno == EINTR)
				continue;
			FILE *ferr = fopen("log.txt", "a");
			fprintf(ferr, "%s: read failed (pos %zu): ", __FUNCTION__, pos);
			fclose(ferr);
			perror("");
		    return -1;
		}
		else if (rc == 0)
		    break;
		pos += rc;
	}
	return pos;
}

static int recv_packet_header_m(struct pkt_header *hdr, size_t len)
{
	if (len < sizeof(*hdr)) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: given buffer to small to contain packet header\n", __FUNCTION__);
			fclose(ferr);
		return -1;
	}
	if (recv_len_m(STDIN_FILENO, hdr, sizeof(*hdr)) != sizeof(*hdr))
		return -1;
	return 0;
}

int write_packet_m(struct pkt_header *hdr, int fd)
{
	size_t totlen = sizeof(*hdr) + ntohs(hdr->datalen);
	ssize_t retval = write(fd, hdr, totlen);
	if (retval != totlen) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: could not write all bytes to stdout\n", __FUNCTION__);
			fclose(ferr);
		return -1;
	} else if (retval < 0) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: failed to write bytes of stdout: ", __FUNCTION__);
			fclose(ferr);
		perror("");
		return -1;
	}
	return 0;
}

static int send_packet_m(struct radium_session *session, struct pkt_header *hdr)
{
	hdr->version = RadiumVersion_2;
	hdr->datalen = htons(hdr->datalen);
	if (hdr->encrypted)
	{
		if (!session->using_encryption || !session->handshake_done) {
			FILE *ferr = fopen("log.txt", "a");
			fprintf(ferr, "%s: no session key to encrypt packet\n", __FUNCTION__);
			fclose(ferr);
			return -1;
		}
		if (os_random(hdr->iv, RADIUM_IV_LEN) < 0) {
			FILE *ferr = fopen("log.txt", "a");
			fprintf(ferr, "%s: failed to generate random encryption IV\n", __FUNCTION__);
			fclose(ferr);
			return -1;
		}
		if (crypt_streamcipher(session->session_key, RADIUM_SESSION_KEY_LEN, hdr->iv, RADIUM_IV_LEN,
			hdr->data, ntohs(hdr->datalen), hdr->data, ntohs(hdr->datalen)) < 0) {
			FILE *ferr = fopen("log.txt", "a");
			fprintf(ferr, "%s: error encryptiong data payload of packet\n", __FUNCTION__);
			fclose(ferr);
			return -1;
		}
		calculate_hmac_sha1(session->session_key, RADIUM_SESSION_KEY_LEN, hdr,
			sizeof(*hdr) + ntohs(hdr->datalen), hdr->hmac, RADIUM_HMAC_LEN);
		return write_packet_m(hdr, session->fd);
	}
	else
	{
		return write_packet_m(hdr, session->fd);
	}
}

static int send_packet_m_tlvs(struct radium_session *session, enum PacketType msgtype, int encrypted,
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

	int retval = send_packet_m(session, hdr);
	free(buffer);
	return retval;
}

#define send_packet_m_one_tlv(session, msgtype, encrypted, tlvtype, tlvsize, tlvdata) \
	send_packet_m_tlvs(session, msgtype, encrypted, tlvtype, tlvsize, tlvdata, 0, 0, NULL)
#define send_packet_m_no_tlvs(session, msgtype) \
	send_packet_m_tlvs(session, msgtype, 0, 0, 0, NULL, 0, 0, NULL)

static int send_error_m(struct radium_session *session, const char *format, ...)
{
	char strerror[256];
	va_list vargs;

	va_start(vargs, format);
	vsnprintf(strerror, sizeof(strerror), format, vargs);
	va_end(vargs);

	return send_packet_m_one_tlv(session, Packet_Error, 0, Tlv_Error, strlen(strerror), strerror);
}

int read_packet_m(uint8_t *packet, size_t len)
{
	struct pkt_header *hdr = (struct pkt_header *)packet;
	if (recv_packet_header_m(hdr, len) < 0) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: failed to read packet header\n", __FUNCTION__);
			fclose(ferr);
		return -1;
	}
	if (len < sizeof(*hdr) + ntohs(hdr->datalen)) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: given buffer not large enough to save full packet (%d < %zu)\n",
			__FUNCTION__, ntohs(hdr->datalen), len - sizeof(*hdr));
			fclose(ferr);
		return -1;
	}
	if (recv_len_m(STDIN_FILENO, hdr + 1, ntohs(hdr->datalen)) != ntohs(hdr->datalen)) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: failed to read packet body (%d bytes)\n", __FUNCTION__, ntohs(hdr->datalen));
			fclose(ferr);
		return -1;
	}
	return 0;
}

static int radium_decrypt_data_m(struct radium_session *session, struct pkt_header *hdr)
{
	if (!hdr->encrypted)
		return 0;
	else if (!session->using_encryption || !session->handshake_done) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: received encrypted data but don't have session key to decrypt it\n", __FUNCTION__);
			fclose(ferr);
		return -1;
	}
	if (crypt_streamcipher(session->session_key, RADIUM_SESSION_KEY_LEN, hdr->iv, RADIUM_IV_LEN,
		hdr->data, ntohs(hdr->datalen), hdr->data, ntohs(hdr->datalen)) < 0) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: error decrypting data payload of packet\n", __FUNCTION__);
			fclose(ferr);
		return -1;
	}
	return 0;
}

static int radium_parse_data_m(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	uint8_t *data = hdr->data;
	int len = ntohs(hdr->datalen);
	memset(tlvs, 0, sizeof(*tlvs));
	size_t pos = 0;
	while (pos < len && len - pos >= 2)
	{
		if (data[pos + 1] > len - pos - 2) {
			send_error_m(session, "%s: not enough data left for element type %d (need %d bytes but only %d left)\n",
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
	if (pos != len) {
		send_error_m(session, "%s: packet contained %d bytes of trailing data\n", __FUNCTION__, len - pos);
		return -1;
	}
	return 0;
}

static int send_client_hello_plaintext_m(struct radium_session *session)
{
	return send_packet_m_no_tlvs(session, Packet_ClientHello);
}

static int send_server_hello_m(struct radium_session *session)
{
	if (session->using_encryption) {
		assert(!is_all_zero(session->server_nonce, RADIUM_NONCE_LEN));
		return send_packet_m_one_tlv(session, Packet_ServerHello, 0,
			Tlv_Nonce, RADIUM_NONCE_LEN, session->server_nonce);
	} else {
		return send_packet_m_no_tlvs(session, Packet_ServerHello);
	}
}

static int send_client_hello_secretkey_m(struct radium_session *session)
{
	if (os_random(session->client_nonce, RADIUM_NONCE_LEN) < 0) {
		fprintf(stderr, "%s: failed to generate random nonce\n", __FUNCTION__);
		return -1;
	}
	return send_packet_m_one_tlv(session, Packet_ClientHello, 0,
		Tlv_Nonce, RADIUM_NONCE_LEN, session->client_nonce);
}

static int process_client_hello_m(struct radium_session *ssession, struct radium_session *csession, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	if (csession->using_encryption)
	{
		csession->using_encryption = 1==1;
		if (tlvs->nonce_len != RADIUM_NONCE_LEN) {
			send_error_m(csession, "%s: nonce in ClientHello was not %d bytes\n", __FUNCTION__, tlvs->nonce_len);
			return -1;
		}
		memcpy(csession->client_nonce, tlvs->nonce, RADIUM_NONCE_LEN);
		memcpy(ssession->client_nonce, tlvs->nonce, RADIUM_NONCE_LEN);
		/*if (os_random(csession->server_nonce, RADIUM_NONCE_LEN) < 0) {
			FILE *ferr = fopen("log.txt", "a");
			fprintf(ferr, "%s: failed to generate server nonce\n", __FUNCTION__);
			fclose(ferr);
			return -1;
		}
		derive_session_key(csession->secretkey, sizeof(csession->secretkey), csession->client_nonce, RADIUM_NONCE_LEN,
			csession->server_nonce, RADIUM_NONCE_LEN, csession->session_key, RADIUM_SESSION_KEY_LEN);*/
	}
	memcpy(ssession->client_nonce, tlvs->nonce, RADIUM_NONCE_LEN);

	FILE *ferr = fopen("log.txt", "a");
	fprintf(ferr, "server hello sent\n");
	fclose(ferr);
	return send_client_hello_secretkey_m(ssession);
}

static int process_server_hello_m(struct radium_session *ssession, struct radium_session *csession, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	if (ssession->using_encryption)
	{
		if (tlvs->nonce == NULL) {
			send_error_m(ssession, "%s: server did include a nonce in ServerHello\n", __FUNCTION__);
			return -1;
		} else if (tlvs->nonce_len != RADIUM_NONCE_LEN) {
			send_error_m(ssession, "%s: nonce in ServerHello was not %d bytes\n", __FUNCTION__, tlvs->nonce_len);
			return -1;
		}
		memcpy(ssession->server_nonce, tlvs->nonce, RADIUM_NONCE_LEN);
		memcpy(csession->server_nonce, tlvs->nonce, RADIUM_NONCE_LEN);
		//derive_session_key(ssession->secretkey, sizeof(session->secretkey), session->client_nonce, RADIUM_NONCE_LEN,
		//	session->server_nonce, RADIUM_NONCE_LEN, session->session_key, RADIUM_SESSION_KEY_LEN);
	}
	ssession->handshake_done = 1;
	csession->handshake_done = 1;
	return send_server_hello_m(csession);
}

static int send_output_m(struct radium_session *session, const char *output)
{
	if (strlen(output) > 256) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: output string too large (%ld characters)\n", __FUNCTION__, strlen(output));
			fclose(ferr);
		return -1;
	}
	return send_packet_m_one_tlv(session, Packet_Output, session->using_encryption,
		Tlv_Output, strlen(output), output);
}

static int send_command_m(struct radium_session *ssession, struct radium_session *csession, struct radium_tlvs *tlvs)
{
	if (strlen(tlvs->command) > 256) {
		FILE *ferr = fopen("log.txt", "a");
		fprintf(ferr, "%s: given command too long (%ld characters)\n", __FUNCTION__, strlen(tlvs->command));
			fclose(ferr);
		return -1;
	}
	if (tlvs->password[0] != '\0') {
		return send_packet_m_tlvs(ssession, Packet_Command, ssession->using_encryption,
			Tlv_Command, strlen(tlvs->command), tlvs->command,
			Tlv_Password, strlen(tlvs->password), tlvs->password);
	} else {
		return send_packet_m_one_tlv(ssession, Packet_Command, ssession->using_encryption,
			Tlv_Command, strlen(tlvs->command), tlvs->command);
	}
}

static int process_command_m(struct radium_session *ssession, struct radium_session *csession, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	if (!csession->handshake_done) {
		send_error_m(csession, "%s: received unexpected command packet\n", __FUNCTION__);
		return -1;
	} else if (csession->using_encryption && !hdr->encrypted) {
		send_error_m(csession, "%s: received command that was not encrypted\n", __FUNCTION__);
		return -1;
	} else if (tlvs->command == NULL) {
		send_error_m(csession, "%s: command packet did not contain a command string element\n", __FUNCTION__);
		return -1;
	}
	if (tlvs->command_len == 4 && timingsafe_memcmp(tlvs->command, "ping", 4) == 0)
	{
		return send_output_m(csession, "pong");
	}
	else if (tlvs->command_len == 8 && timingsafe_memcmp(tlvs->command, "get_flag", 8) == 0)
	{
		sleep(1);
		if (tlvs->password == NULL)
			return send_output_m(csession, "Command get_flag requires a valid password");
		memcpy(csession->password, tlvs->password, tlvs->password_len);
		memcpy(ssession->password, tlvs->password, tlvs->password_len);

		return send_command_m(ssession, csession, tlvs);
	}
	else
	{
		return send_output_m(csession, "Unknown command");
	}
}

static int process_output_m(struct radium_session *session, struct pkt_header *hdr, struct radium_tlvs *tlvs)
{
	if (!session->handshake_done) {
		send_error_m(session, "%s: received unexpected output packet\n", __FUNCTION__);
		return -1;
	} else if (session->using_encryption && !hdr->encrypted) {
		send_error_m(session, "%s: received output packet that was not encrypted\n", __FUNCTION__);
		return -1;
	} else if (tlvs->output == NULL) {
		send_error_m(session, "%s: output packet did not contain an output string element\n", __FUNCTION__);
		return -1;
	}
	FILE *f = fopen("flag.txt", "a");
	if (f == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	fprintf(f, "Output: %.*s\n", tlvs->output_len, tlvs->output);
	//FILE *ferr = fopen("log.txt", "a");\nfprintf(ferr, "Output: %.*s\n", tlvs->output_len, tlvs->output);
	return 0;
}

static int process_packet_m(struct radium_session *ssession, struct radium_session *csession, struct pkt_header *hdr)
{
	struct radium_tlvs tlvs;
	if (hdr->version != RadiumVersion_2)
		return -1;
	if (radium_decrypt_data_m(csession, hdr) < 0)
		return -1;
	if (radium_parse_data_m(csession, hdr, &tlvs) < 0)
		return -1;
	FILE *ferr;
	switch (hdr->msgtype) {
		case Packet_ClientHello:
			// send client hello with client nonce
			ferr = fopen("log.txt", "a");
			fprintf(ferr, "client hello rcvd\n");
			fclose(ferr);
			return process_client_hello_m(ssession, csession, hdr, &tlvs);
		case Packet_ServerHello:
			// send server hello with server hash
			ferr = fopen("log.txt", "a");
			fprintf(ferr, "server hello rcvd\n");
			fclose(ferr);
			return process_server_hello_m(ssession, csession, hdr, &tlvs);
		case Packet_Command:
			// send command with client hash
			ferr = fopen("log.txt", "a");
			fprintf(ferr, "command rcvd\n");
			fclose(ferr);
			return process_command_m(ssession, csession, hdr, &tlvs);
		case Packet_Output:
	ferr = fopen("log.txt", "a");
	fprintf(ferr, "output rcvd\n");
	fclose(ferr);
			return process_output_m(ssession, hdr, &tlvs);
		default:
			send_error_m(ssession, "%s: unknown packet type\n", __FUNCTION__);
			return -1;
	}
}

static int mitm_loop(struct radium_session *ssession,struct radium_session *csession)
{
	uint8_t buffer[2048];
	struct pkt_header *hdr = (struct pkt_header *)buffer;

	FILE *ferr = fopen("log.txt", "a");
	fprintf(ferr, "just before reading\n");
	fclose(ferr);
	while (read_packet_m(buffer, sizeof(buffer)) >= 0)
	{
		if (process_packet_m(ssession, csession, hdr) < 0)
			return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct radium_session ssession, csession;
	memset(&ssession, 0, sizeof(ssession));
	memset(&csession, 0, sizeof(csession));

	if (radium_read_config(&ssession, "radium.conf") < 0)
		return -1;
	if (radium_read_config(&csession, "radium.conf") < 0)
		return -1;

	// Terminate program after 5 seconds (prevent possible DoS)
	alarm(5);

	csession.fd = STDERR_FILENO;
	ssession.fd = STDOUT_FILENO;

	csession.is_server = 1;
	ssession.is_server = 0;
	csession.using_encryption = 1==1;
	ssession.using_encryption = 1==1;
	return mitm_loop(&ssession, &csession);
}