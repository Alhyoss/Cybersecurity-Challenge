#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>
#include <openssl/sha.h>

#define RADIUM_NONCE_LEN	32
#define RADIUM_HMAC_LEN		SHA_DIGEST_LENGTH
#define RADIUM_IV_LEN		16

#define PACKED __attribute__((packed))

enum RadiumVersion {
	RadiumVersion_1 = 1,
	RadiumVersion_2 = 2
};

enum PacketType {
	Packet_ClientHello = 0,
	Packet_ServerHello = 1,
	Packet_Command = 2,
	Packet_Output = 3,
	Packet_Error = 4 /* XXX used to inform the endpoint about malformed packets */
};

enum TlvType {
	Tlv_Nonce = 1,
	Tlv_Password = 2,
	Tlv_Command = 3,
	Tlv_Output = 4,
	Tlv_Error = 5
};

struct radium_tlvs {
	const uint8_t *nonce;
	uint8_t nonce_len;

	const uint8_t *password;
	uint8_t password_len;

	const uint8_t *command;
	uint8_t command_len;

	const uint8_t *output;
	uint8_t output_len;
};

struct pkt_header {
	// Basic header
	uint8_t version;
	uint8_t msgtype;
	// Used to encrypt and authenticate using symmetric keys
	uint8_t iv[RADIUM_IV_LEN];
	uint8_t hmac[RADIUM_HMAC_LEN];
	// Type-length-value data specific to each message type
	uint8_t encrypted;
	uint16_t datalen;
	uint8_t data[0];
} PACKED;

int read_packet(uint8_t *packet, size_t len);
int write_packet(struct pkt_header *hdr);

#endif // PACKETS_H
