#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <arpa/inet.h>

#include "packets.h"

static ssize_t recv_len(int fd, void *packet, size_t n)
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
			fprintf(stderr, "%s: read failed (pos %zu): ", __FUNCTION__, pos);
			perror("");
		    return -1;
		}
		else if (rc == 0)
		    break;
		pos += rc;
	}

	return pos;
}

static int recv_packet_header(struct pkt_header *hdr, size_t len)
{
	if (len < sizeof(*hdr)) {
		fprintf(stderr, "%s: given buffer to small to contain packet header\n", __FUNCTION__);
		return -1;
	}

	if (recv_len(STDIN_FILENO, hdr, sizeof(*hdr)) != sizeof(*hdr))
		return -1;

	return 0;
}

int read_packet(uint8_t *packet, size_t len)
{
	struct pkt_header *hdr = (struct pkt_header *)packet;

	if (recv_packet_header(hdr, len) < 0) {
		fprintf(stderr, "%s: failed to read packet header\n", __FUNCTION__);
		return -1;
	}

	if (len < sizeof(*hdr) + ntohs(hdr->datalen)) {
		fprintf(stderr, "%s: given buffer not large enough to save full packet (%d < %zu)\n",
			__FUNCTION__, ntohs(hdr->datalen), len - sizeof(*hdr));
		return -1;
	}

	if (recv_len(STDIN_FILENO, hdr + 1, ntohs(hdr->datalen)) != ntohs(hdr->datalen)) {
		fprintf(stderr, "%s: failed to read packet body (%d bytes)\n", __FUNCTION__, ntohs(hdr->datalen));
		return -1;
	}

	//hexdump(packet, expected_length, "Received");
	return 0;
}

int write_packet(struct pkt_header *hdr)
{
	//hexdump(packet, length, "Sending");
	size_t totlen = sizeof(*hdr) + ntohs(hdr->datalen);

	ssize_t retval = write(STDOUT_FILENO, hdr, totlen);
	if (retval != totlen) {
		fprintf(stderr, "%s: could not write all bytes to stdout\n", __FUNCTION__);
		return -1;
	} else if (retval < 0) {
		fprintf(stderr, "%s: failed to write bytes of stdout: ", __FUNCTION__);
		perror("");
		return -1;
	}

	return 0;
}

