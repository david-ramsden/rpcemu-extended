/*
 * Carry frames between two machines over a real relay.
 *
 * Not a unit test and not part of ctest: it needs a relay running and a
 * machine enrolled against its certificate authority, which CI has no way to
 * arrange. tests/test_nexus_framing.c covers the wire format on its own; this
 * is the question that one cannot answer - whether a frame put in one end
 * comes out of the other, through QUIC, through the relay's switch, and back
 * up through reassembly.
 *
 *   nexus_frame_probe send <host> <port> <ca> <crt> <key> <src-mac>
 *   nexus_frame_probe recv <host> <port> <ca> <crt> <key>
 *
 * The receiver joins and waits. The sender joins and transmits two frames: one
 * that fits in a datagram and one that does not, so both the whole path and
 * the fragmented one are exercised. A full-size frame is the normal shape of a
 * ShareFS file copy, which is what makes the second case the one that matters.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "net_quic.h"
#include "nexus_framing.h"

extern int net_quic_connect(const char *host, int port, const char *ca_file,
    const char *cert_file, const char *key_file);

/* Filled in by the stub network_nat_inject_packet() below, which is where a
   frame arrives when it has come all the way back up the wire. */
int received_count;
int received_len[8];
unsigned char received[8][NEXUS_MAX_FRAME];

static void
sleep_ms(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long) (ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

/** Poll for a while, the way the emulator's instruction loop does. */
static void
pump(int ms)
{
	int i;

	for (i = 0; i < ms; i++) {
		net_quic_poll();
		sleep_ms(1);
	}
}

/** An Ethernet frame: broadcast, from @src, with recognisable filler. */
static void
make_frame(unsigned char *buf, size_t len, const unsigned char *src, unsigned char tag)
{
	size_t i;

	memset(buf, 0xff, 6);
	memcpy(buf + 6, src, 6);
	buf[12] = 0x08;
	buf[13] = 0x00;
	for (i = 14; i < len; i++) {
		buf[i] = (unsigned char) (tag + i);
	}
}

static int
parse_mac(const char *text, unsigned char *out)
{
	unsigned v[6];
	int i;

	if (sscanf(text, "%x:%x:%x:%x:%x:%x",
	        &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
		return -1;
	}
	for (i = 0; i < 6; i++) {
		out[i] = (unsigned char) v[i];
	}
	return 0;
}

static int
join(const char *host, const char *port, const char *ca, const char *crt,
    const char *key)
{
	int waited;

	if (net_quic_connect(host, atoi(port), ca, crt, key) != 0) {
		printf("FAIL: could not start the connection\n");
		return -1;
	}

	for (waited = 0; waited < 15000; waited++) {
		net_quic_poll();
		if (net_quic_is_connected()) {
			printf("joined after %d ms\n", waited);
			return 0;
		}
		sleep_ms(1);
	}

	printf("FAIL: never joined\n");
	return -1;
}

int
main(int argc, char *argv[])
{
	unsigned char frame[NEXUS_MAX_FRAME];
	unsigned char mac[6];

	if (argc < 7) {
		fprintf(stderr, "usage: %s send|recv <host> <port> <ca> <crt> <key> [src-mac]\n",
		    argv[0]);
		return 2;
	}

	if (join(argv[2], argv[3], argv[4], argv[5], argv[6]) != 0) {
		return 1;
	}

	if (strcmp(argv[1], "recv") == 0) {
		int i;

		printf("waiting for frames\n");
		pump(12000);

		printf("\n%d frame(s) arrived\n", received_count);
		for (i = 0; i < received_count; i++) {
			printf("  %d bytes, from %02x:%02x:%02x:%02x:%02x:%02x\n",
			    received_len[i], received[i][6], received[i][7],
			    received[i][8], received[i][9], received[i][10],
			    received[i][11]);
		}

		net_quic_close();
		return received_count > 0 ? 0 : 1;
	}

	if (argc < 8 || parse_mac(argv[7], mac) != 0) {
		fprintf(stderr, "send needs a source MAC, the one this machine enrolled\n");
		return 2;
	}

	/* Settle first: the receiver has to have joined, or the relay has
	   nowhere to forward to and drops the frame rather than holding it. */
	pump(2000);

	printf("sending a 64-byte frame\n");
	make_frame(frame, 64, mac, 1);
	net_quic_tx(frame, 64);
	pump(1500);

	printf("sending a 1514-byte frame, which has to be fragmented\n");
	make_frame(frame, 1514, mac, 2);
	net_quic_tx(frame, 1514);
	pump(3000);

	printf("sending a 1149-byte frame, the largest that travels whole\n");
	make_frame(frame, 1149, mac, 3);
	net_quic_tx(frame, 1149);
	pump(2000);

	printf("\nsent\n");
	net_quic_close();
	return 0;
}
