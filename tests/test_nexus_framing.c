/*
 * The Nexus wire format: Ethernet frames in QUIC datagrams.
 *
 * WHY THIS IS STRICTER THAN IT LOOKS. This is one half of a wire format whose
 * other half is Python, in the relay. A disagreement between them is not
 * something either side can detect at run time: a frame is sent, and the other
 * end makes something else of it or nothing at all. So the numbers and the
 * exact bytes are pinned here rather than derived, and changing one means
 * changing relay/nexus_relay/framing.py to match.
 *
 * ★ THE CASE THAT MATTERS MOST is that a 1514-byte frame produces TWO
 * datagrams rather than none. A QUIC library accepts an oversized datagram and
 * then discards it in silence - measured against the relay's, 214 dropped in
 * one run with nothing in any log. RISC OS fragments ShareFS bulk writes at
 * the Ethernet MTU, so full-size frames are the normal shape of a file copy:
 * the traffic people would actually notice going missing.
 */

#include <stdio.h>
#include <string.h>

#include "nexus_framing.h"

static int failures;

static void
check(const char *what, int ok)
{
	printf("  %-62s %s\n", what, ok ? "ok" : "FAIL");
	if (!ok) {
		failures++;
	}
}

/** An Ethernet frame: destination, source, type, then filler. */
static size_t
make_frame(uint8_t *buf, size_t len, uint8_t tag)
{
	size_t i;

	memset(buf, 0xff, 6);			/* broadcast */
	buf[6] = 0x02; buf[7] = 0x00; buf[8] = 0xde;
	buf[9] = 0xad; buf[10] = 0xbe; buf[11] = 0x01;
	buf[12] = 0x08; buf[13] = 0x00;		/* IPv4 */
	for (i = 14; i < len; i++) {
		buf[i] = (uint8_t) (tag + i);
	}
	return len;
}

int
main(void)
{
	uint8_t frame[NEXUS_MAX_FRAME];
	uint8_t back[NEXUS_MAX_FRAME];
	NexusDatagram out[NEXUS_MAX_PIECES];
	NexusPiece piece;
	NexusReassembler r;
	int n;

	printf("the constants the relay also uses\n");
	/* Pinned, not computed: the relay has the same numbers written down,
	   and a change on one side has to be a change on both. */
	check("a QUIC datagram carries 1152 bytes", NEXUS_MAX_DATAGRAM == 1152);
	check("a whole frame may be 1149", NEXUS_MAX_WHOLE == 1149);
	check("a piece of one may be 1145", NEXUS_MAX_PIECE == 1145);
	check("the header is 3 bytes, 7 when fragmented",
	    NEXUS_HEADER_LEN == 3 && NEXUS_FRAGMENT_HEADER_LEN == 7);
	/* The largest frame needs two pieces; the ceiling is three. The slack
	   is what a peer's claimed count is checked against, so it is a limit
	   on state rather than a capacity this ever uses. */
	check("the fragment count ceiling is 3", NEXUS_MAX_PIECES == 3);
	check("1522 bytes needs two pieces",
	    (NEXUS_MAX_FRAME + NEXUS_MAX_PIECE - 1) / NEXUS_MAX_PIECE == 2);

	printf("\na frame that fits travels whole\n");
	make_frame(frame, 64, 0);
	n = nexus_encode(1, frame, 64, 0, out);
	check("one datagram", n == 1);
	check("3 bytes of header on top", out[0].len == 64 + 3);
	check("flags are zero", out[0].bytes[0] == 0x00);
	check("the vlan is big-endian in bytes 1-2",
	    out[0].bytes[1] == 0x00 && out[0].bytes[2] == 0x01);
	check("the frame follows byte for byte",
	    memcmp(out[0].bytes + 3, frame, 64) == 0);

	printf("\nthe vlan is carried, not assumed\n");
	n = nexus_encode(4094, frame, 64, 0, out);
	check("4094 encodes as 0x0f 0xfe",
	    n == 1 && out[0].bytes[1] == 0x0f && out[0].bytes[2] == 0xfe);
	check("vlan 0 is refused", nexus_encode(0, frame, 64, 0, out) == -1);
	check("vlan 4095 is refused", nexus_encode(4095, frame, 64, 0, out) == -1);

	printf("\n★ a full-size frame produces two datagrams, never none\n");
	/* The case the whole file exists for. 1514 is what RISC OS emits for a
	   ShareFS bulk write, and what an oversized datagram would lose. */
	make_frame(frame, 1514, 7);
	n = nexus_encode(1, frame, 1514, 0x1234, out);
	check("two datagrams", n == 2);
	check("neither exceeds what a datagram carries",
	    n == 2 && out[0].len <= NEXUS_MAX_DATAGRAM &&
	    out[1].len <= NEXUS_MAX_DATAGRAM);
	check("the first is full", out[0].len == 7 + NEXUS_MAX_PIECE);
	check("the second holds the rest",
	    out[1].len == 7 + (size_t) (1514 - NEXUS_MAX_PIECE));
	check("both carry the fragment flag",
	    out[0].bytes[0] == 0x80 && out[1].bytes[0] == 0x80);
	check("both carry the same frame id",
	    out[0].bytes[3] == 0x12 && out[0].bytes[4] == 0x34 &&
	    out[1].bytes[3] == 0x12 && out[1].bytes[4] == 0x34);
	check("they are numbered 0 and 1 of 2",
	    out[0].bytes[5] == 0 && out[0].bytes[6] == 2 &&
	    out[1].bytes[5] == 1 && out[1].bytes[6] == 2);

	printf("\nthe boundary between whole and split\n");
	make_frame(frame, NEXUS_MAX_WHOLE, 1);
	check("1149 still goes whole",
	    nexus_encode(1, frame, NEXUS_MAX_WHOLE, 0, out) == 1);
	make_frame(frame, NEXUS_MAX_WHOLE + 1, 1);
	check("1150 is split",
	    nexus_encode(1, frame, NEXUS_MAX_WHOLE + 1, 0, out) == 2);

	printf("\nlengths the wire format does not allow\n");
	check("13 bytes is refused", nexus_encode(1, frame, 13, 0, out) == -1);
	check("14 bytes is accepted", nexus_encode(1, frame, 14, 0, out) == 1);
	check("1522 is accepted", nexus_encode(1, frame, 1522, 0, out) == 2);
	check("1523 is refused", nexus_encode(1, frame, 1523, 0, out) == -1);

	printf("\ndecoding what we encoded\n");
	make_frame(frame, 100, 3);
	n = nexus_encode(42, frame, 100, 0, out);
	check("decodes", n == 1 &&
	    nexus_decode(out[0].bytes, out[0].len, &piece) == 0);
	check("the vlan came back", piece.vlan == 42);
	check("it is a whole frame", piece.count == 1);
	check("the body is the frame",
	    piece.body_len == 100 && memcmp(piece.body, frame, 100) == 0);

	printf("\ndatagrams that are not ours are refused, not guessed at\n");
	check("shorter than a header",
	    nexus_decode((const uint8_t *) "\x00\x00", 2, &piece) == -1);
	{
		uint8_t bad[32];

		memset(bad, 0, sizeof(bad));
		bad[0] = 0x01;			/* a reserved bit */
		bad[2] = 1;
		check("a reserved flag bit set",
		    nexus_decode(bad, sizeof(bad), &piece) == -1);

		bad[0] = 0x00;
		bad[1] = 0x00; bad[2] = 0x00;	/* vlan 0 */
		check("vlan 0 on the wire",
		    nexus_decode(bad, sizeof(bad), &piece) == -1);

		bad[1] = 0x0f; bad[2] = 0xff;	/* vlan 4095 */
		check("vlan 4095 on the wire",
		    nexus_decode(bad, sizeof(bad), &piece) == -1);

		/* A fragment claiming to be one of one, or one of many more
		   than can exist: both would make the reassembler hold state
		   for a frame that will never arrive. */
		memset(bad, 0, sizeof(bad));
		bad[0] = 0x80; bad[2] = 1; bad[5] = 0; bad[6] = 1;
		check("a fragment count of 1",
		    nexus_decode(bad, sizeof(bad), &piece) == -1);

		bad[6] = NEXUS_MAX_PIECES + 1;
		check("a fragment count beyond the maximum",
		    nexus_decode(bad, sizeof(bad), &piece) == -1);

		bad[5] = 2; bad[6] = 2;
		check("piece 2 of 2", nexus_decode(bad, sizeof(bad), &piece) == -1);
	}

	printf("\na split frame comes back whole\n");
	memset(&r, 0, sizeof(r));
	make_frame(frame, 1514, 9);
	n = nexus_encode(1, frame, 1514, 0xabcd, out);
	check("two to send", n == 2);
	check("the first completes nothing",
	    nexus_decode(out[0].bytes, out[0].len, &piece) == 0 &&
	    nexus_reassemble(&r, &piece, 1000, back, sizeof(back)) == 0);
	check("one frame is pending", nexus_reassembly_pending(&r) == 1);
	check("the second completes it",
	    nexus_decode(out[1].bytes, out[1].len, &piece) == 0 &&
	    nexus_reassemble(&r, &piece, 1000, back, sizeof(back)) == 1514);
	check("byte for byte what went in", memcmp(back, frame, 1514) == 0);
	check("nothing is left pending", nexus_reassembly_pending(&r) == 0);
	check("nothing was dropped", r.dropped == 0);

	printf("\npieces may arrive in either order\n");
	memset(&r, 0, sizeof(r));
	n = nexus_encode(1, frame, 1514, 1, out);
	(void) nexus_decode(out[1].bytes, out[1].len, &piece);
	(void) nexus_reassemble(&r, &piece, 1000, back, sizeof(back));
	(void) nexus_decode(out[0].bytes, out[0].len, &piece);
	check("last first still reassembles",
	    nexus_reassemble(&r, &piece, 1000, back, sizeof(back)) == 1514);
	check("and is identical", memcmp(back, frame, 1514) == 0);

	printf("\nan incomplete frame is dropped rather than held\n");
	/* What a wire does with a damaged frame, and the reason a peer cannot
	   make this hold memory by sending only first fragments. */
	memset(&r, 0, sizeof(r));
	n = nexus_encode(1, frame, 1514, 2, out);
	(void) nexus_decode(out[0].bytes, out[0].len, &piece);
	(void) nexus_reassemble(&r, &piece, 1000, back, sizeof(back));
	check("pending before the deadline", nexus_reassembly_pending(&r) == 1);
	nexus_reassembly_expire(&r, 1000 + NEXUS_REASSEMBLY_MS - 1);
	check("still pending one millisecond before it",
	    nexus_reassembly_pending(&r) == 1);
	nexus_reassembly_expire(&r, 1000 + NEXUS_REASSEMBLY_MS);
	check("gone at the deadline", nexus_reassembly_pending(&r) == 0);
	check("and counted", r.dropped == 1);
	/* The sibling arriving late must not resurrect it. */
	(void) nexus_decode(out[1].bytes, out[1].len, &piece);
	check("a late sibling completes nothing",
	    nexus_reassemble(&r, &piece, 2000, back, sizeof(back)) == 0);

	printf("\nstate a peer can cause is bounded\n");
	memset(&r, 0, sizeof(r));
	{
		int i;

		/* Nine first-fragments of nine different frames, into eight
		   slots. The ninth must evict rather than grow. */
		for (i = 0; i < NEXUS_MAX_PARTIAL + 1; i++) {
			n = nexus_encode(1, frame, 1514, (uint16_t) (100 + i), out);
			(void) nexus_decode(out[0].bytes, out[0].len, &piece);
			(void) nexus_reassemble(&r, &piece, 1000 + (uint32_t) i,
			    back, sizeof(back));
		}
		check("never more than the maximum in flight",
		    nexus_reassembly_pending(&r) <= NEXUS_MAX_PARTIAL);
		check("the evicted one was counted", r.dropped >= 1);
	}

	printf("\na peer that changes its mind is refused\n");
	memset(&r, 0, sizeof(r));
	{
		uint8_t a[64], b[64];

		/* Two pieces of frame 1, the second claiming a different count.
		   Believing it would mean waiting for a piece that is not
		   coming. */
		memset(a, 0, sizeof(a));
		a[0] = 0x80; a[2] = 1; a[3] = 0; a[4] = 1; a[5] = 0; a[6] = 2;
		memcpy(b, a, sizeof(b));
		b[5] = 1; b[6] = 2;

		(void) nexus_decode(a, sizeof(a), &piece);
		(void) nexus_reassemble(&r, &piece, 1000, back, sizeof(back));

		/* Same frame id, count now 2 in the header but the reassembler
		   was told 2 already - so use a genuinely different count. */
		b[6] = 2;
		b[5] = 1;
		(void) nexus_decode(b, sizeof(b), &piece);
		piece.count = 3;	/* as if the peer had said 3 */
		check("the partial frame is abandoned",
		    nexus_reassemble(&r, &piece, 1000, back, sizeof(back)) == 0);
		check("and counted as dropped", r.dropped >= 1);
	}

	printf("\nan empty piece still counts as arrived\n");
	/* A well-behaved sender never produces one, so this is about what a
	   peer can do rather than what the relay does: treating "no bytes" as
	   "not here" would mean a frame that never completes. */
	memset(&r, 0, sizeof(r));
	{
		uint8_t hdr[NEXUS_FRAGMENT_HEADER_LEN];
		uint8_t whole[NEXUS_FRAGMENT_HEADER_LEN + 20];

		memset(whole, 0, sizeof(whole));
		whole[0] = 0x80; whole[2] = 1; whole[5] = 0; whole[6] = 2;
		memset(whole + NEXUS_FRAGMENT_HEADER_LEN, 0xaa, 20);
		(void) nexus_decode(whole, sizeof(whole), &piece);
		(void) nexus_reassemble(&r, &piece, 1000, back, sizeof(back));

		memset(hdr, 0, sizeof(hdr));
		hdr[0] = 0x80; hdr[2] = 1; hdr[5] = 1; hdr[6] = 2;
		check("an empty second piece is accepted",
		    nexus_decode(hdr, sizeof(hdr), &piece) == 0 &&
		    piece.body_len == 0);
		check("and completes the frame at 20 bytes",
		    nexus_reassemble(&r, &piece, 1000, back, sizeof(back)) == 20);
	}

	printf("\nan assembled frame too short to be Ethernet is dropped\n");
	memset(&r, 0, sizeof(r));
	{
		uint8_t a[NEXUS_FRAGMENT_HEADER_LEN + 4];
		uint8_t b[NEXUS_FRAGMENT_HEADER_LEN + 4];

		memset(a, 0, sizeof(a));
		a[0] = 0x80; a[2] = 1; a[5] = 0; a[6] = 2;
		memcpy(b, a, sizeof(b));
		b[5] = 1;

		(void) nexus_decode(a, sizeof(a), &piece);
		(void) nexus_reassemble(&r, &piece, 1000, back, sizeof(back));
		(void) nexus_decode(b, sizeof(b), &piece);
		check("8 bytes is not a frame",
		    nexus_reassemble(&r, &piece, 1000, back, sizeof(back)) == 0);
		check("and is counted", r.dropped >= 1);
	}

	printf("\nthe clock wrapping does not expire everything\n");
	/* A 32-bit millisecond clock wraps every 49 days. Comparing the values
	   rather than their difference would make every partial frame look
	   expired for 49 days, once every 49 days. */
	memset(&r, 0, sizeof(r));
	{
		uint32_t near_wrap = 0xffffffffu - 10;

		n = nexus_encode(1, frame, 1514, 5, out);
		(void) nexus_decode(out[0].bytes, out[0].len, &piece);
		(void) nexus_reassemble(&r, &piece, near_wrap, back, sizeof(back));
		check("pending across the wrap",
		    nexus_reassembly_pending(&r) == 1);
		/* 20ms later, which is past zero but not past the deadline. */
		nexus_reassembly_expire(&r, near_wrap + 20);
		check("still pending 20ms later",
		    nexus_reassembly_pending(&r) == 1);
		(void) nexus_decode(out[1].bytes, out[1].len, &piece);
		check("and completes",
		    nexus_reassemble(&r, &piece, near_wrap + 20, back,
		        sizeof(back)) == 1514);
	}

	printf("\n%s\n", failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
