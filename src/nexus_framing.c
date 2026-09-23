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
 * nexus_framing - see nexus_framing.h for the wire format and why it is this.
 *
 * Nothing here allocates. The reassembler carries its buffers inside itself,
 * so the amount of memory a peer can cause to be held is fixed at compile
 * time: NEXUS_MAX_PARTIAL frames of NEXUS_MAX_PIECES pieces, and not a byte
 * more however it behaves.
 */

#include <assert.h>
#include <string.h>

#include "nexus_framing.h"

int
nexus_encode(unsigned vlan, const uint8_t *frame, size_t frame_len,
    uint16_t frame_id, NexusDatagram *out)
{
	size_t offset;
	int count;
	int i;

	assert(frame != NULL);
	assert(out != NULL);

	if (vlan < NEXUS_MIN_VLAN || vlan > NEXUS_MAX_VLAN) {
		return -1;
	}
	if (frame_len < NEXUS_MIN_FRAME || frame_len > NEXUS_MAX_FRAME) {
		return -1;
	}

	/* The common case: it fits, so it goes whole. */
	if (frame_len <= NEXUS_MAX_WHOLE) {
		out[0].bytes[0] = 0;
		out[0].bytes[1] = (uint8_t) (vlan >> 8);
		out[0].bytes[2] = (uint8_t) (vlan & 0xff);
		memcpy(out[0].bytes + NEXUS_HEADER_LEN, frame, frame_len);
		out[0].len = NEXUS_HEADER_LEN + frame_len;
		return 1;
	}

	/* Ceiling division: the last piece is whatever is left over. */
	count = (int) ((frame_len + NEXUS_MAX_PIECE - 1) / NEXUS_MAX_PIECE);
	assert(count >= 2 && count <= NEXUS_MAX_PIECES);

	offset = 0;
	for (i = 0; i < count; i++) {
		size_t piece_len = frame_len - offset;

		if (piece_len > NEXUS_MAX_PIECE) {
			piece_len = NEXUS_MAX_PIECE;
		}

		out[i].bytes[0] = NEXUS_FLAG_FRAGMENT;
		out[i].bytes[1] = (uint8_t) (vlan >> 8);
		out[i].bytes[2] = (uint8_t) (vlan & 0xff);
		out[i].bytes[3] = (uint8_t) (frame_id >> 8);
		out[i].bytes[4] = (uint8_t) (frame_id & 0xff);
		out[i].bytes[5] = (uint8_t) i;
		out[i].bytes[6] = (uint8_t) count;
		memcpy(out[i].bytes + NEXUS_FRAGMENT_HEADER_LEN, frame + offset,
		    piece_len);
		out[i].len = NEXUS_FRAGMENT_HEADER_LEN + piece_len;

		offset += piece_len;
	}
	assert(offset == frame_len);

	return count;
}

int
nexus_decode(const uint8_t *datagram, size_t len, NexusPiece *out)
{
	unsigned vlan;
	uint8_t flags;

	assert(datagram != NULL);
	assert(out != NULL);

	if (len < NEXUS_HEADER_LEN) {
		return -1;
	}

	flags = datagram[0];

	/* Reserved bits are sent as zero. Anything else is a later version of
	   the protocol, and guessing at it is worse than dropping it. */
	if ((flags & NEXUS_FLAG_RESERVED) != 0) {
		return -1;
	}

	vlan = ((unsigned) datagram[1] << 8) | datagram[2];
	if (vlan < NEXUS_MIN_VLAN || vlan > NEXUS_MAX_VLAN) {
		return -1;
	}

	memset(out, 0, sizeof(*out));
	out->vlan = vlan;

	if ((flags & NEXUS_FLAG_FRAGMENT) == 0) {
		out->body = datagram + NEXUS_HEADER_LEN;
		out->body_len = len - NEXUS_HEADER_LEN;
		out->count = 1;
		return 0;
	}

	if (len < NEXUS_FRAGMENT_HEADER_LEN) {
		return -1;
	}

	out->index = datagram[5];
	out->count = datagram[6];

	if (out->count < 2 || out->count > NEXUS_MAX_PIECES) {
		return -1;
	}
	if (out->index >= out->count) {
		return -1;
	}

	out->frame_id = (uint16_t) (((unsigned) datagram[3] << 8) | datagram[4]);
	out->body = datagram + NEXUS_FRAGMENT_HEADER_LEN;
	out->body_len = len - NEXUS_FRAGMENT_HEADER_LEN;

	return 0;
}

/*
 * A millisecond clock that wraps is still usable if differences are taken
 * rather than the values compared: (int32_t)(a - b) is the signed distance
 * and stays correct across the wrap. Comparing the values directly would make
 * everything look expired for 49 days once every 49 days.
 */
static int
reached(uint32_t now_ms, uint32_t deadline_ms)
{
	return (int32_t) (now_ms - deadline_ms) >= 0;
}

void
nexus_reassembly_expire(NexusReassembler *r, uint32_t now_ms)
{
	unsigned i;

	assert(r != NULL);

	for (i = 0; i < NEXUS_MAX_PARTIAL; i++) {
		if (r->partial[i].in_use && reached(now_ms, r->partial[i].deadline_ms)) {
			r->partial[i].in_use = 0;
			r->dropped++;
		}
	}
}

unsigned
nexus_reassembly_pending(const NexusReassembler *r)
{
	unsigned i, n = 0;

	assert(r != NULL);

	for (i = 0; i < NEXUS_MAX_PARTIAL; i++) {
		if (r->partial[i].in_use) {
			n++;
		}
	}
	return n;
}

/** The slot holding this frame, or NEXUS_MAX_PARTIAL if it is not held. */
static unsigned
find_partial(const NexusReassembler *r, unsigned vlan, uint16_t frame_id)
{
	unsigned i;

	for (i = 0; i < NEXUS_MAX_PARTIAL; i++) {
		if (r->partial[i].in_use && r->partial[i].vlan == vlan &&
		    r->partial[i].frame_id == frame_id) {
			return i;
		}
	}
	return NEXUS_MAX_PARTIAL;
}

/**
 * A free slot, evicting the one closest to expiry if there is none.
 *
 * Rather than growing: the oldest is the least likely to complete, and a peer
 * sending only first fragments must not be able to make this unbounded.
 */
static unsigned
take_slot(NexusReassembler *r)
{
	unsigned i, oldest = NEXUS_MAX_PARTIAL;

	for (i = 0; i < NEXUS_MAX_PARTIAL; i++) {
		if (!r->partial[i].in_use) {
			return i;
		}
		if (oldest == NEXUS_MAX_PARTIAL ||
		    (int32_t) (r->partial[i].deadline_ms -
		               r->partial[oldest].deadline_ms) < 0) {
			oldest = i;
		}
	}

	r->partial[oldest].in_use = 0;
	r->dropped++;
	return oldest;
}

size_t
nexus_reassemble(NexusReassembler *r, const NexusPiece *piece, uint32_t now_ms,
    uint8_t *out, size_t out_size)
{
	unsigned slot;
	size_t total;
	unsigned i;

	assert(r != NULL);
	assert(piece != NULL);
	assert(out != NULL);

	/* A whole frame is not reassembly's business. */
	if (piece->count == 1) {
		if (piece->body_len < NEXUS_MIN_FRAME ||
		    piece->body_len > out_size) {
			r->dropped++;
			return 0;
		}
		memcpy(out, piece->body, piece->body_len);
		return piece->body_len;
	}

	nexus_reassembly_expire(r, now_ms);

	if (piece->body_len > NEXUS_MAX_PIECE) {
		r->dropped++;
		return 0;
	}

	slot = find_partial(r, piece->vlan, piece->frame_id);

	if (slot == NEXUS_MAX_PARTIAL) {
		slot = take_slot(r);
		memset(&r->partial[slot], 0, sizeof(r->partial[slot]));
		r->partial[slot].in_use = 1;
		r->partial[slot].vlan = piece->vlan;
		r->partial[slot].frame_id = piece->frame_id;
		r->partial[slot].count = piece->count;
		r->partial[slot].deadline_ms = now_ms + NEXUS_REASSEMBLY_MS;
	} else if (r->partial[slot].count != piece->count) {
		/* The peer changed its mind about how many pieces there are. */
		r->partial[slot].in_use = 0;
		r->dropped++;
		return 0;
	}

	/* A repeated index overwrites rather than accumulating, so a peer
	   cannot inflate the total by sending one piece many times. */
	if (!r->partial[slot].present[piece->index]) {
		r->partial[slot].present[piece->index] = 1;
		r->partial[slot].have++;
	}
	memcpy(r->partial[slot].piece[piece->index], piece->body, piece->body_len);
	r->partial[slot].piece_len[piece->index] = piece->body_len;

	total = 0;
	for (i = 0; i < r->partial[slot].count; i++) {
		total += r->partial[slot].piece_len[i];
	}

	if (total > NEXUS_MAX_FRAME) {
		r->partial[slot].in_use = 0;
		r->dropped++;
		return 0;
	}

	if (r->partial[slot].have < r->partial[slot].count) {
		return 0;
	}

	r->partial[slot].in_use = 0;

	if (total < NEXUS_MIN_FRAME || total > out_size) {
		r->dropped++;
		return 0;
	}

	total = 0;
	for (i = 0; i < r->partial[slot].count; i++) {
		memcpy(out + total, r->partial[slot].piece[i],
		    r->partial[slot].piece_len[i]);
		total += r->partial[slot].piece_len[i];
	}

	return total;
}
