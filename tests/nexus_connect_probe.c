/*
 * Drive net_quic.c against a real relay.
 *
 * Not a unit test and not part of ctest: it needs a relay running and a
 * machine enrolled against its certificate authority, which CI has no way to
 * arrange. It is the thing to run when the question is "does the client
 * actually talk to the relay", which no amount of testing the framing can
 * answer.
 *
 *   nexus_connect_probe <host> <port> <ca.crt> <machine.crt> <machine.key>
 *
 * Exits 0 once the connection is up and a network has been joined, which is
 * the whole of the handshake path: UDP, QUIC, ALPN, the client certificate,
 * the relay's authorisation call to Nexus, and the control stream in both
 * directions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "net_quic.h"

int
main(int argc, char *argv[])
{
	time_t deadline;
	int polls = 0;

	if (argc != 6) {
		fprintf(stderr,
		    "usage: %s <host> <port> <ca.crt> <machine.crt> <machine.key>\n",
		    argv[0]);
		return 2;
	}

	printf("connecting to %s:%s\n", argv[1], argv[2]);

	if (net_quic_connect(argv[1], atoi(argv[2]), argv[3], argv[4], argv[5]) != 0) {
		printf("FAIL: could not start the connection\n");
		return 1;
	}

	/* The emulator polls from its instruction loop, thousands of times a
	   second. This is the same shape, slowed to something a person can
	   watch. */
	deadline = time(NULL) + 15;
	while (time(NULL) < deadline) {
		net_quic_poll();
		polls++;

		if (net_quic_is_connected()) {
			printf("\nPASS: connected and joined after %d polls\n", polls);
			net_quic_close();
			return 0;
		}

		{
			struct timespec ts = { 0, 1000000 };	/* 1ms */

			nanosleep(&ts, NULL);
		}
	}

	printf("\nFAIL: gave up after %d polls\n", polls);
	printf("  wants a connection: %s\n",
	    net_quic_wants_connection() ? "yes" : "no");
	net_quic_close();
	return 1;
}
