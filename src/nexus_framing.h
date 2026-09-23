/*
  RPCEmu - An Acorn system emulator

  Copyright (C) 2026 Andy Timmins

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * nexus_framing - Ethernet frames in QUIC datagrams, for the Nexus wire.
 *
 * Three bytes of header and then the frame, byte for byte, destination MAC
 * first: no JSON and no base64. The network tag lives outside the frame
 * rather than as an 802.1Q tag inside it, so the frame crossing the wire is
 * the frame the guest sent.
 *
 *     byte 0      flags    bit 7: a fragment header follows. bits 6-0 reserved
 *     bytes 1-2   network  the VLAN this frame belongs to, 1..4094
 *     bytes 3-4   frame id  ) fragments
 *     byte 5      index     ) only
 *     byte 6      count     )
 *
 * ★ THE RULE THIS FILE EXISTS TO ENFORCE.
 *
 * A QUIC library accepts a datagram of any size and then silently discards one
 * that will not fit - measured against the relay's: 214 dropped in a single
 * run, with no error and nothing in any log. An oversized frame must therefore
 * never reach it. Everything outgoing goes through nexus_encode(), which
 * fragments rather than hoping, and a frame too large even for that is refused
 * loudly.
 *
 * A transport that refuses an oversized frame has a bug that is found in an
 * afternoon. One that drops it silently has a bug reported six months later as
 * "large file copies are unreliable", by somebody who cannot reproduce it.
 *
 * ★ THIS IS ONE HALF OF A WIRE FORMAT.
 *
 * The relay implements the other half, in Python, and the two must agree byte
 * for byte. tests/test_nexus_framing.c pins the numbers and the exact bytes;
 * changing anything here means changing relay/nexus_relay/framing.py too, and
 * a disagreement is not something either side can detect at run time - it
 * shows up as frames that vanish.
 */

#ifndef NEXUS_FRAMING_H
#define NEXUS_FRAMING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The datagram budget, measured rather than estimated.
 *
 * The QUIC packet size stays at 1200 - the floor QUIC guarantees is
 * carryable - because neither library does path MTU discovery: raising it
 * asserts a path rather than finding one, and a peer behind a tunnel, a PPPoE
 * link or a VPN would then black-hole every full-size packet.
 *
 * The overhead is the QUIC library's, not QUIC's: aioquic needs 30 bytes at
 * this packet size and ngtcp2 needs 43. It is set for the larger, with margin,
 * because a datagram that exceeds it is built, accepted and then dropped with
 * nothing reported at either end.
 *
 * Shared with relay/nexus_relay/framing.py. The two have to agree.
 */
#define NEXUS_QUIC_PACKET_SIZE	1200
#define NEXUS_DATAGRAM_OVERHEAD	48
#define NEXUS_MAX_DATAGRAM	(NEXUS_QUIC_PACKET_SIZE - NEXUS_DATAGRAM_OVERHEAD)

#define NEXUS_HEADER_LEN	3
#define NEXUS_FRAGMENT_HEADER_LEN	7

/** The largest frame that travels whole, and the largest piece of a split one. */
#define NEXUS_MAX_WHOLE		(NEXUS_MAX_DATAGRAM - NEXUS_HEADER_LEN)		/* 1149 */
#define NEXUS_MAX_PIECE		(NEXUS_MAX_DATAGRAM - NEXUS_FRAGMENT_HEADER_LEN)	/* 1145 */

#define NEXUS_FLAG_FRAGMENT	0x80u
#define NEXUS_FLAG_RESERVED	0x7fu

/** 802.1Q's range, so the ids map across if the relay ever bridges to a real switch. */
#define NEXUS_MIN_VLAN		1
#define NEXUS_MAX_VLAN		4094

/** An Ethernet frame, with room for a tag the guest might have added itself. */
#define NEXUS_MAX_FRAME		1522
#define NEXUS_MIN_FRAME		14

/** Enough pieces for the largest frame and no more: 2 today. */
#define NEXUS_MAX_PIECES	(((NEXUS_MAX_FRAME + NEXUS_MAX_PIECE - 1) / NEXUS_MAX_PIECE) + 1)

/** One incomplete frame is held this long, in milliseconds, then dropped. */
#define NEXUS_REASSEMBLY_MS	100

/** At most this many partial frames in flight at once, per connection. */
#define NEXUS_MAX_PARTIAL	8

/** One datagram, ready to hand to the QUIC library. */
typedef struct {
	uint8_t	bytes[NEXUS_MAX_DATAGRAM];
	size_t	len;
} NexusDatagram;

/**
 * One frame as the datagrams that carry it.
 *
 * Writes one datagram for anything that fits and several for anything that
 * does not. It never produces something too large to send, which is the whole
 * point of going through here.
 *
 * @param vlan      The network, 1..4094
 * @param frame     The complete Ethernet frame, destination MAC first
 * @param frame_len Its length, 14..1522
 * @param frame_id  Identifies the pieces of one frame to the far end; only
 *                  used when the frame has to be split, and wraps at 16 bits
 * @param out       Where to write them, NEXUS_MAX_PIECES entries
 * @return          How many datagrams were written, or -1 if the vlan or the
 *                  length is outside what the wire format allows
 */
extern int nexus_encode(unsigned vlan, const uint8_t *frame, size_t frame_len,
    uint16_t frame_id, NexusDatagram *out);

/** One datagram taken apart: either a whole frame or one piece of one. */
typedef struct {
	unsigned	vlan;
	const uint8_t	*body;		/**< into the caller's datagram, not copied */
	size_t		body_len;
	uint16_t	frame_id;
	uint8_t		index;
	uint8_t		count;		/**< 1 when the datagram holds a whole frame */
} NexusPiece;

/**
 * Parse one datagram.
 *
 * Fails rather than returning something half understood: a datagram that
 * cannot be read is one from a peer we should not be guessing on behalf of.
 *
 * @param datagram  The bytes as they arrived
 * @param len       How many
 * @param out       Filled in on success; out->body points into @datagram, so
 *                  it is valid only as long as that buffer is
 * @return          0, or -1 if this is not one of ours
 */
extern int nexus_decode(const uint8_t *datagram, size_t len, NexusPiece *out);

/**
 * Puts fragmented frames back together, for one connection.
 *
 * State is bounded on purpose: a peer must not be able to make this hold
 * frames it never finishes. Anything incomplete after NEXUS_REASSEMBLY_MS is
 * dropped, which is what a wire does with a damaged frame.
 *
 * Zero-initialise before first use.
 */
typedef struct {
	struct {
		unsigned	vlan;
		uint16_t	frame_id;
		uint8_t		count;
		uint8_t		have;		/**< how many pieces are present */
		uint32_t	deadline_ms;
		uint8_t		in_use;
		/* Presence is its own flag rather than a length of zero: a peer
		   may send an empty piece, and that must count as arrived or a
		   frame could never complete. */
		uint8_t		present[NEXUS_MAX_PIECES];
		size_t		piece_len[NEXUS_MAX_PIECES];
		uint8_t		piece[NEXUS_MAX_PIECES][NEXUS_MAX_PIECE];
	} partial[NEXUS_MAX_PARTIAL];

	/** Frames given up on: expired, evicted, or malformed once assembled. */
	unsigned long	dropped;
} NexusReassembler;

/**
 * Offer one decoded piece, and take the frame it completed.
 *
 * A whole frame is handed straight back. A fragment is held until its siblings
 * arrive or its deadline passes.
 *
 * @param r        The reassembler
 * @param piece    From nexus_decode()
 * @param now_ms   A monotonic millisecond clock; only differences matter
 * @param out      Where to write the completed frame
 * @param out_size How much room that is, at least NEXUS_MAX_FRAME
 * @return         The frame's length, or 0 if this piece did not complete one
 */
extern size_t nexus_reassemble(NexusReassembler *r, const NexusPiece *piece,
    uint32_t now_ms, uint8_t *out, size_t out_size);

/**
 * Drop anything whose deadline has passed.
 *
 * Called by nexus_reassemble(), and separately when a connection is idle: a
 * partial frame that arrived before a quiet period should not be completed by
 * a piece that turns up much later.
 */
extern void nexus_reassembly_expire(NexusReassembler *r, uint32_t now_ms);

/** How many partial frames are in flight. For tests and diagnostics. */
extern unsigned nexus_reassembly_pending(const NexusReassembler *r);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_FRAMING_H */
