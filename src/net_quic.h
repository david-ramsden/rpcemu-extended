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
 * net_quic - the Nexus Community Network wire.
 *
 * Ethernet frames over QUIC to a relay, which switches them between the
 * machines on a network. Where net_json.h carries frames to a server somebody
 * runs, this carries them to a hosted one that knows who each machine is: the
 * connection is mutually authenticated with a certificate the machine enrolled
 * for, and the relay refuses frames claiming a MAC address that is not the
 * one it certified.
 *
 * ★ THE SAME SHAPE AS net_json.h, DELIBERATELY.
 *
 * init, close, is_connected, wants_connection, tx, poll - so network-nat.c
 * chooses between the wires at the call sites it already has, rather than
 * growing a third way of doing the same thing. A machine is on ONE
 * machine-to-machine wire: both are hubs from the guest's point of view, and a
 * machine on two would receive every frame twice.
 *
 * ★ POLLED FROM THE EMULATOR THREAD. NO THREAD OF ITS OWN.
 *
 * This is worth stating because QUIC usually implies an event loop. The
 * emulator already polls its wire thousands of times a second, from inside the
 * instruction loop, which is more often than QUIC's timers need servicing. So
 * net_quic_poll() does three things on each call: reads whatever UDP has
 * arrived, services ngtcp2's expiry, and sends whatever that produced.
 *
 * What that trades away is worth knowing: while the emulator is paused in the
 * debugger, nothing is polled, so a long pause loses the connection. Reconnect
 * handles it, and a thread would not be a small change.
 *
 * ★ THE CONTROL STREAM IS TWO STREAMS.
 *
 * The relay opens its own bidirectional stream to say "hello" before the
 * client has opened anything, and adopts the client's first bidirectional
 * stream as the one it reads. So this reads on the relay's stream id and
 * writes on its own, and they are not the same number. Conflating them gives a
 * machine that connects, is authorised, and then silently never joins
 * anything.
 *
 * Messages are JSON, one per line:
 *
 *     <- {"hello": "<ulid>", "networks": [1, 7]}    which networks it may use
 *     -> {"join": 1}                                 asking for one
 *     <- {"joined": 1}                               granted
 *     <- {"error": "not entitled", "network": 7}     refused, with a reason
 *     -> {"leave": 1}
 *     <- {"left": 1}
 *
 * Frames never go on it: a large file copy must not be able to delay a
 * disconnection notice.
 */

#ifndef NET_QUIC_H
#define NET_QUIC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The relay, which is not a setting.
 *
 * Everybody who joins Nexus joins the same one: a machine's networks are the
 * relay's answer at authorisation rather than something chosen here, so there
 * is nothing for a user to configure and no way to end up on a wire their
 * peers are not on.
 *
 * RPCEMU_NEXUS_RELAY overrides it, as "host" or "host:port", for developing
 * against a relay of your own. It is deliberately an environment variable and
 * not a setting: pointing a machine somewhere else is a thing to do while
 * working on Nexus, not a choice to offer.
 */
#define NEXUS_RELAY_HOST	"nexus.branchthroughzero.co.uk"
#define NEXUS_RELAY_PORT	33445

/**
 * Connect to the relay.
 *
 * Does nothing and reports failure when the machine has no relay configured or
 * has not enrolled, which is how network-nat.c decides whether to use another
 * wire instead. A relay that is configured but cannot be reached is reported,
 * and net_quic_poll() keeps trying for it.
 *
 * @return 0 if this machine is on the Nexus wire, connected or waiting to be;
 *         -1 if there is nothing to connect to
 */
extern int net_quic_init(void);

/**
 * Connect to a relay, named rather than read from the configuration.
 *
 * What net_quic_init() calls once it has the machine's settings, and what a
 * test uses to reach a relay without a machine behind it.
 *
 * @param host      The relay
 * @param port      Its port
 * @param ca_file   The certificate authority that issued the relay's
 *                  certificate, pinned rather than taken from the system store
 * @param cert_file This machine's certificate
 * @param key_file  Its private key
 * @return          0 if the connection has started, -1 with the reason logged
 */
extern int net_quic_connect(const char *host, int port, const char *ca_file,
    const char *cert_file, const char *key_file);

/**
 * Disconnect, release the socket, and stop wanting a connection.
 */
extern void net_quic_close(void);

/**
 * Whether frames are reaching the relay.
 *
 * True only once the handshake has finished, the relay has authorised this
 * machine, and it has joined at least one network - before that there is
 * nowhere for a frame to go.
 *
 * @return 1 if connected and joined, 0 if not
 */
extern int net_quic_is_connected(void);

/**
 * Whether this machine belongs to a relay, connected or not.
 *
 * The wires are alternatives, so a machine waiting for its relay must not be
 * put on another one in the meantime: it would be on both when the relay came
 * back, and receive every frame twice.
 *
 * @return 1 if a relay is configured for this machine
 */
extern int net_quic_wants_connection(void);

/**
 * Send a frame the guest has transmitted.
 *
 * Fragmented if it does not fit in a datagram, which is nexus_framing.c's job
 * and not optional: the QUIC library accepts an oversized datagram and then
 * discards it without a word.
 *
 * Queued rather than sent: building a packet and putting it on the socket both
 * happen in net_quic_poll(), so there is one place that talks to the network
 * and one place that decides what goes in a packet. A frame offered when the
 * queue is full is dropped, which is what a wire does when it is busy.
 *
 * @param frame     Complete Ethernet frame
 * @param frame_len Length in bytes
 */
extern void net_quic_tx(const uint8_t *frame, int frame_len);

/**
 * Carry the connection forward and deliver what arrived.
 *
 * Reads datagrams, services QUIC's timers, writes whatever that produced, and
 * hands complete frames to the guest. Called often from the emulator's
 * instruction loop; it never blocks.
 *
 * @return the number of frames delivered to the guest
 */
extern int net_quic_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* NET_QUIC_H */
