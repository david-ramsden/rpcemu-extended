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
 * net_quic - see net_quic.h for the wire and the control protocol.
 *
 * The parts, in the order they run:
 *
 *   connect()    a UDP socket and an ngtcp2 client connection
 *   poll()       read what arrived, service the timers, write what is owed
 *   control      JSON lines on a stream, in both directions
 *   frames       QUIC datagrams, through nexus_framing.c
 *
 * ngtcp2 does not own the socket and does not know the time. It is given
 * packets and asked what to send; everything else here is that plumbing.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "socket-compat.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include "net_quic.h"
#include "nexus_framing.h"
#include "network.h"
#include "network-nat.h"
#include "rpcemu.h"

/** The protocol and its version. A relay that has retired ours says so at the
    handshake, rather than after letting us on to send things nobody reads. */
#define NEXUS_ALPN		"nexus/1"

/** Cold and warm retry, as net_json uses: ten seconds before a first
    connection has ever worked, five after one has. */
#define NEXUS_RETRY_COLD_SECONDS	10
#define NEXUS_RETRY_WARM_SECONDS	5

/** How long a handshake may take before it is given up on. */
#define NEXUS_HANDSHAKE_SECONDS		10

/** One JSON control message. Generous for a line that is usually 30 bytes. */
#define NEXUS_CONTROL_LINE	512

/** The control stream's read buffer. A line longer than this is a peer doing
    something we have no reason to accommodate. */
#define NEXUS_CONTROL_BUFFER	4096

/** Everything about the connection, or nothing when there is not one. */
static struct {
	int		fd;		/**< UDP socket, -1 when closed */
	ngtcp2_conn	*conn;
	WOLFSSL_CTX	*ssl_ctx;
	WOLFSSL		*ssl;

	/* ngtcp2 reaches its connection through this, set as wolfSSL's app
	   data. The crypto helper requires it and does not take a user
	   pointer of its own. */
	ngtcp2_crypto_conn_ref	conn_ref;

	struct sockaddr_storage	local_addr;
	socklen_t		local_addrlen;
	struct sockaddr_storage	remote_addr;
	socklen_t		remote_addrlen;

	int		want_connection;	/**< a relay is configured */
	int		handshake_done;
	int		ever_connected;
	time_t		next_attempt;
	time_t		handshake_deadline;

	/* The control stream is two: the relay opens one to speak on, and
	   adopts the first one we open to listen on. */
	int64_t		tx_stream;	/**< ours, -1 until opened */
	int64_t		rx_stream;	/**< the relay's, -1 until it speaks */

	char		rx_line[NEXUS_CONTROL_BUFFER];
	size_t		rx_line_len;

	/* Control messages waiting to go out. ngtcp2 asks for data when it has
	   room, rather than being handed it, so it is queued here. */
	uint8_t		tx_queue[NEXUS_CONTROL_BUFFER];
	size_t		tx_queue_len;
	size_t		tx_queue_sent;	/**< acknowledged by ngtcp2, not by the peer */

	unsigned	vlan;		/**< the network joined, 0 until then */
	int		joined;

	NexusReassembler	reasm;
	uint16_t		next_frame_id;
} q;

/* ------------------------------------------------------------------------ */
/* Clocks                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * ngtcp2's clock: nanoseconds, monotonic, and only differences matter.
 */
static ngtcp2_tstamp
timestamp(void)
{
#ifdef _WIN32
	LARGE_INTEGER freq, now;

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&now);
	return (ngtcp2_tstamp) ((now.QuadPart * 1000000000ull) / (uint64_t) freq.QuadPart);
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp) ts.tv_nsec;
#endif
}

/** The same clock in milliseconds, for the reassembler. */
static uint32_t
timestamp_ms(void)
{
	return (uint32_t) (timestamp() / 1000000ull);
}

/* ------------------------------------------------------------------------ */
/* ngtcp2 plumbing                                                           */
/* ------------------------------------------------------------------------ */

static ngtcp2_conn *
get_conn(ngtcp2_crypto_conn_ref *ref)
{
	(void) ref;
	return q.conn;
}

/**
 * Random bytes, for connection ids and path challenges.
 *
 * Not cryptographic quality, and does not need to be: a connection id is an
 * identifier rather than a secret, and everything that must be unguessable is
 * wolfSSL's business.
 */
static void
rand_bytes(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
	size_t i;

	(void) ctx;
	for (i = 0; i < destlen; i++) {
		dest[i] = (uint8_t) (rand() & 0xff);
	}
}

static int
get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
    size_t cidlen, void *user_data)
{
	size_t i;

	(void) conn;
	(void) user_data;

	for (i = 0; i < cidlen; i++) {
		cid->data[i] = (uint8_t) (rand() & 0xff);
	}
	cid->datalen = cidlen;

	for (i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; i++) {
		token[i] = (uint8_t) (rand() & 0xff);
	}

	return 0;
}

static int
handshake_completed(ngtcp2_conn *conn, void *user_data)
{
	(void) conn;
	(void) user_data;

	q.handshake_done = 1;
	q.ever_connected = 1;
	rpclog("net_quic: handshake complete\n");
	return 0;
}

/* Declared here, defined with the rest of the control protocol below. */
static void control_line_received(const char *line);
static int datagram_received(const uint8_t *data, size_t len);

static int
recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data,
    void *stream_user_data)
{
	size_t i;

	(void) conn;
	(void) flags;
	(void) offset;
	(void) user_data;
	(void) stream_user_data;

	/* Both streams are the control stream. The relay opens one of its own
	   to say "hello", because at that point the client has opened nothing,
	   and replies on ours once it arrives. Reading only the first stream
	   heard from means "hello" is seen and "joined" is not: the machine
	   connects, is authorised, and then sits there, because the answer
	   arrived and was thrown away.
	   One line buffer between them: they carry one conversation, and the
	   relay finishes its line on the first before using the second. */
	if (q.rx_stream == -1) {
		q.rx_stream = stream_id;
	}

	for (i = 0; i < datalen; i++) {
		if (data[i] == '\n') {
			q.rx_line[q.rx_line_len] = '\0';
			if (q.rx_line_len > 0) {
				control_line_received(q.rx_line);
			}
			q.rx_line_len = 0;
			continue;
		}
		if (q.rx_line_len + 1 < sizeof(q.rx_line)) {
			q.rx_line[q.rx_line_len++] = (char) data[i];
		} else {
			/* A line this long is not one of ours. Drop what is
			   buffered rather than truncating into something that
			   might parse as a different message. */
			q.rx_line_len = 0;
		}
	}

	ngtcp2_conn_extend_max_stream_offset(q.conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(q.conn, datalen);

	return 0;
}

static int
recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data,
    size_t datalen, void *user_data)
{
	(void) conn;
	(void) flags;
	(void) user_data;

	(void) datagram_received(data, datalen);
	return 0;
}

/* ------------------------------------------------------------------------ */
/* The control protocol                                                      */
/* ------------------------------------------------------------------------ */

/**
 * The value of a top-level JSON key, without a JSON parser.
 *
 * The relay's control messages are a handful of flat objects with integer or
 * string values, all written by one program. A parser would be the right
 * answer for arbitrary JSON; for six known shapes it is a dependency and an
 * attack surface bought for nothing.
 *
 * @return a pointer to the first character of the value, or NULL
 */
static const char *
json_value(const char *line, const char *key)
{
	char quoted[64];
	const char *p;

	if ((size_t) snprintf(quoted, sizeof(quoted), "\"%s\"", key) >= sizeof(quoted)) {
		return NULL;
	}

	p = strstr(line, quoted);
	if (p == NULL) {
		return NULL;
	}

	p += strlen(quoted);
	while (*p == ' ' || *p == ':' || *p == '\t') {
		p++;
	}

	return *p != '\0' ? p : NULL;
}

/** A top-level integer, or -1. */
static long
json_int(const char *line, const char *key)
{
	const char *v = json_value(line, key);

	if (v == NULL || *v < '0' || *v > '9') {
		return -1;
	}
	return strtol(v, NULL, 10);
}

/** Queue a control message. Sent by the writer when ngtcp2 has room. */
static void
control_send(const char *json)
{
	const size_t len = strlen(json);

	if (q.tx_queue_len + len + 1 > sizeof(q.tx_queue)) {
		rpclog("net_quic: control queue full, dropping %s\n", json);
		return;
	}

	memcpy(q.tx_queue + q.tx_queue_len, json, len);
	q.tx_queue_len += len;
	q.tx_queue[q.tx_queue_len++] = '\n';
}

/**
 * The commons, or the first network the relay says we may use.
 *
 * VLAN 1 is the commons by definition, so it is preferred when offered. A
 * machine entitled only to a private network joins that instead.
 */
static unsigned
choose_network(const char *line)
{
	const char *p = json_value(line, "networks");
	unsigned first = 0;

	if (p == NULL || *p != '[') {
		return 0;
	}

	for (p++; *p != '\0' && *p != ']'; p++) {
		if (*p >= '0' && *p <= '9') {
			const unsigned n = (unsigned) strtoul(p, (char **) &p, 10);

			if (n == 1) {
				return 1;
			}
			if (first == 0) {
				first = n;
			}
			if (*p == '\0') {
				break;
			}
		}
	}

	return first;
}

static void
control_line_received(const char *line)
{
	long value;

	if (json_value(line, "hello") != NULL) {
		char message[64];

		q.vlan = choose_network(line);
		if (q.vlan == 0) {
			rpclog("net_quic: the relay authorised this machine but "
			       "offered no networks\n");
			return;
		}

		rpclog("net_quic: authorised; joining network %u\n", q.vlan);
		snprintf(message, sizeof(message), "{\"join\": %u}", q.vlan);
		control_send(message);
		return;
	}

	value = json_int(line, "joined");
	if (value > 0) {
		q.joined = 1;
		q.vlan = (unsigned) value;
		rpclog("net_quic: joined network %ld\n", value);
		return;
	}

	value = json_int(line, "left");
	if (value > 0) {
		q.joined = 0;
		rpclog("net_quic: left network %ld\n", value);
		return;
	}

	if (json_value(line, "error") != NULL) {
		/* Logged whole: the relay says why, and guessing at which
		   reason it was would lose the part that helps. */
		rpclog("net_quic: the relay refused: %s\n", line);
		return;
	}
}

/* ------------------------------------------------------------------------ */
/* Frames                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * One datagram from the relay, taken apart and given to the guest.
 *
 * @return 1 if a frame reached the guest
 */
static int
datagram_received(const uint8_t *data, size_t len)
{
	uint8_t frame[NEXUS_MAX_FRAME];
	NexusPiece piece;
	size_t frame_len;

	if (nexus_decode(data, len, &piece) != 0) {
		return 0;
	}

	/* A frame for a network this machine is not on should not have been
	   sent, but arriving is not the same as being wanted. */
	if (piece.vlan != q.vlan) {
		return 0;
	}

	frame_len = nexus_reassemble(&q.reasm, &piece, timestamp_ms(), frame,
	    sizeof(frame));
	if (frame_len == 0) {
		return 0;
	}

	/* No receive filter here, unlike the other wires. The relay is a
	   MAC-learning switch: it sends a unicast frame only to the machine
	   that owns the address, so anything arriving is either for us or a
	   broadcast that is for everybody. */
	return network_nat_inject_packet(frame, (int) frame_len) ? 1 : 0;
}

void
net_quic_tx(const uint8_t *frame, int frame_len)
{
	NexusDatagram datagrams[NEXUS_MAX_PIECES];
	int n, i;

	if (!net_quic_is_connected() || frame == NULL || frame_len <= 0) {
		return;
	}

	n = nexus_encode(q.vlan, frame, (size_t) frame_len, q.next_frame_id++,
	    datagrams);
	if (n < 0) {
		rpclog("net_quic: refusing to send a %d byte frame\n", frame_len);
		return;
	}

	for (i = 0; i < n; i++) {
		ngtcp2_vec vec;
		ngtcp2_ssize written;

		vec.base = datagrams[i].bytes;
		vec.len = datagrams[i].len;

		written = ngtcp2_conn_writev_datagram(q.conn, NULL, NULL, NULL, 0,
		    NULL, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &vec, 1, timestamp());
		if (written < 0) {
			rpclog("net_quic: could not queue a datagram: %s\n",
			    ngtcp2_strerror((int) written));
			return;
		}
	}
}

/* ------------------------------------------------------------------------ */
/* The connection                                                            */
/* ------------------------------------------------------------------------ */

int
net_quic_wants_connection(void)
{
	return q.want_connection;
}

int
net_quic_is_connected(void)
{
	return q.conn != NULL && q.handshake_done && q.joined;
}

void
net_quic_close(void)
{
	if (q.conn != NULL) {
		ngtcp2_conn_del(q.conn);
		q.conn = NULL;
	}
	if (q.ssl != NULL) {
		wolfSSL_free(q.ssl);
		q.ssl = NULL;
	}
	if (q.ssl_ctx != NULL) {
		wolfSSL_CTX_free(q.ssl_ctx);
		q.ssl_ctx = NULL;
	}
	if (q.fd >= 0) {
		closesocket(q.fd);
		q.fd = -1;
	}

	q.handshake_done = 0;
	q.joined = 0;
	q.vlan = 0;
	q.tx_stream = -1;
	q.rx_stream = -1;
	q.rx_line_len = 0;
	q.tx_queue_len = 0;
	q.tx_queue_sent = 0;
	q.want_connection = 0;
	memset(&q.reasm, 0, sizeof(q.reasm));
}

/**
 * A UDP socket connected to the relay, and the addresses ngtcp2 needs.
 *
 * connect() on UDP does not send anything: it fixes the peer so send() works
 * and the kernel fills in a local address, which ngtcp2 must be told.
 *
 * @return 0, or -1 with the reason logged
 */
static int
open_socket(const char *host, int port)
{
	struct addrinfo hints, *res, *ai;
	char service[16];
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	snprintf(service, sizeof(service), "%d", port);

	rc = getaddrinfo(host, service, &hints, &res);
	if (rc != 0) {
		rpclog("net_quic: cannot resolve %s:%d\n", host, port);
		return -1;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		int fd = (int) socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (fd < 0) {
			continue;
		}
		if (connect(fd, ai->ai_addr, (socklen_t) ai->ai_addrlen) != 0) {
			closesocket(fd);
			continue;
		}

		q.local_addrlen = sizeof(q.local_addr);
		if (getsockname(fd, (struct sockaddr *) &q.local_addr,
		        &q.local_addrlen) != 0) {
			closesocket(fd);
			continue;
		}

		memcpy(&q.remote_addr, ai->ai_addr, ai->ai_addrlen);
		q.remote_addrlen = (socklen_t) ai->ai_addrlen;

		socket_set_nonblocking(fd);
		q.fd = fd;
		freeaddrinfo(res);
		return 0;
	}

	freeaddrinfo(res);
	rpclog("net_quic: cannot reach %s:%d\n", host, port);
	return -1;
}

/**
 * wolfSSL configured for QUIC, with our certificate and the relay's CA.
 *
 * @return 0, or -1 with the reason logged
 */
static int
open_tls(const char *server_name, const char *ca_file, const char *cert_file,
    const char *key_file)
{
	q.ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
	if (q.ssl_ctx == NULL) {
		rpclog("net_quic: no TLS context\n");
		return -1;
	}

	if (ngtcp2_crypto_wolfssl_configure_client_context(q.ssl_ctx) != 0) {
		rpclog("net_quic: wolfSSL has no QUIC support in this build\n");
		return -1;
	}

	/* The CA that issued the relay's certificate, which Nexus handed over
	   at enrolment. Pinned rather than trusted from the system store: the
	   relay is ours, and anything else offering a certificate for it is
	   not something to be talked into accepting. */
	if (wolfSSL_CTX_load_verify_locations(q.ssl_ctx, ca_file, NULL) != WOLFSSL_SUCCESS) {
		rpclog("net_quic: cannot read the CA certificate %s\n", ca_file);
		return -1;
	}
	wolfSSL_CTX_set_verify(q.ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);

	/* Ours, which is how the relay knows which machine this is. */
	if (wolfSSL_CTX_use_certificate_chain_file(q.ssl_ctx, cert_file) != WOLFSSL_SUCCESS) {
		rpclog("net_quic: cannot read the machine certificate %s\n", cert_file);
		return -1;
	}
	if (wolfSSL_CTX_use_PrivateKey_file(q.ssl_ctx, key_file,
	        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
		rpclog("net_quic: cannot read the machine key %s\n", key_file);
		return -1;
	}

	q.ssl = wolfSSL_new(q.ssl_ctx);
	if (q.ssl == NULL) {
		rpclog("net_quic: no TLS session\n");
		return -1;
	}

	/* The crypto helper reaches the ngtcp2 connection through this. It
	   takes no user pointer of its own, so the app data is the only route
	   and leaving it out fails inside the handshake rather than here. */
	q.conn_ref.get_conn = get_conn;
	q.conn_ref.user_data = NULL;
	wolfSSL_set_app_data(q.ssl, &q.conn_ref);

	wolfSSL_set_connect_state(q.ssl);

	/* Offer a key share in the ClientHello rather than waiting to be asked
	   for one. Without this wolfSSL sends none, and the relay fails inside
	   its own key exchange with nothing to derive a secret from - which
	   surfaces as a handshake that never finishes rather than as an error
	   either end reports. */
	if (wolfSSL_UseKeyShare(q.ssl, WOLFSSL_ECC_SECP256R1) != WOLFSSL_SUCCESS) {
		rpclog("net_quic: cannot offer a key share\n");
		return -1;
	}

	wolfSSL_set_alpn_protos(q.ssl, (const unsigned char *) "\x07" NEXUS_ALPN,
	    1 + (unsigned) strlen(NEXUS_ALPN));
	wolfSSL_UseSNI(q.ssl, WOLFSSL_SNI_HOST_NAME, server_name,
	    (unsigned short) strlen(server_name));

	return 0;
}

/**
 * The ngtcp2 client connection itself.
 *
 * @return 0, or -1 with the reason logged
 */
static int
open_conn(void)
{
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	ngtcp2_cid dcid, scid;
	ngtcp2_path path;
	uint8_t dcid_buf[NGTCP2_MAX_CIDLEN];
	uint8_t scid_buf[NGTCP2_MAX_CIDLEN];
	size_t i;
	int rc;

	memset(&callbacks, 0, sizeof(callbacks));

	/* Everything cryptographic comes from the crypto helper: this is the
	   whole reason ngtcp2 has a wolfSSL backend, and writing any of it by
	   hand would be writing QUIC's key schedule by hand. */
	callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
	callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
	callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
	callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
	callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
	callbacks.update_key = ngtcp2_crypto_update_key_cb;
	callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
	callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

	/* Ours: what the connection is actually for. */
	callbacks.handshake_completed = handshake_completed;
	callbacks.recv_stream_data = recv_stream_data;
	callbacks.recv_datagram = recv_datagram;
	callbacks.rand = rand_bytes;
	callbacks.get_new_connection_id = get_new_connection_id;

	for (i = 0; i < sizeof(dcid_buf); i++) {
		dcid_buf[i] = (uint8_t) (rand() & 0xff);
		scid_buf[i] = (uint8_t) (rand() & 0xff);
	}
	dcid.datalen = sizeof(dcid_buf);
	memcpy(dcid.data, dcid_buf, sizeof(dcid_buf));
	scid.datalen = sizeof(scid_buf);
	memcpy(scid.data, scid_buf, sizeof(scid_buf));

	ngtcp2_settings_default(&settings);
	settings.initial_ts = timestamp();
	/* QUIC's guaranteed floor. Raising it asserts a path rather than
	   finding one - ngtcp2 does no PMTU discovery here - and a peer behind
	   a tunnel would black-hole every full-size packet. nexus_framing.c
	   fragments to suit. */
	settings.max_tx_udp_payload_size = NEXUS_QUIC_PACKET_SIZE;

	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_bidi = 8;
	params.initial_max_streams_uni = 8;
	params.initial_max_stream_data_bidi_local = 256 * 1024;
	params.initial_max_stream_data_bidi_remote = 256 * 1024;
	params.initial_max_data = 1024 * 1024;
	/* Without this the relay may not send datagrams at all, and frames
	   would arrive nowhere while the control stream worked perfectly. */
	params.max_datagram_frame_size = NEXUS_QUIC_PACKET_SIZE;

	path.local.addr = (struct sockaddr *) &q.local_addr;
	path.local.addrlen = q.local_addrlen;
	path.remote.addr = (struct sockaddr *) &q.remote_addr;
	path.remote.addrlen = q.remote_addrlen;
	path.user_data = NULL;

	rc = ngtcp2_conn_client_new(&q.conn, &dcid, &scid, &path,
	    NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, NULL);
	if (rc != 0) {
		rpclog("net_quic: cannot create the connection: %s\n",
		    ngtcp2_strerror(rc));
		return -1;
	}

	ngtcp2_conn_set_tls_native_handle(q.conn, q.ssl);
	return 0;
}

int
net_quic_init(void)
{
	memset(&q, 0, sizeof(q));
	q.fd = -1;
	q.tx_stream = -1;
	q.rx_stream = -1;

	/* Nothing yet reads a relay address or a certificate out of the
	   machine's configuration, so there is nothing to connect to. The
	   settings and the enrolment come next; until then this reports "no
	   relay configured" and network-nat.c uses another wire.

	   net_quic_connect() below is what the settings will call. */
	return -1;
}

/**
 * Connect to a relay. Everything above, in order.
 *
 * Separate from net_quic_init() so it can be driven by a test before the
 * machine settings exist, and so a reconnect is one call rather than a
 * teardown and a re-init.
 *
 * @return 0, or -1 with the reason logged
 */
int
net_quic_connect(const char *host, int port, const char *ca_file,
    const char *cert_file, const char *key_file)
{
	memset(&q, 0, sizeof(q));
	q.fd = -1;
	q.tx_stream = -1;
	q.rx_stream = -1;
	q.want_connection = 1;

	if (open_socket(host, port) != 0 ||
	    open_tls(host, ca_file, cert_file, key_file) != 0 ||
	    open_conn() != 0) {
		net_quic_close();
		q.want_connection = 1;	/* keep retrying; close() cleared it */
		return -1;
	}

	q.handshake_deadline = time(NULL) + NEXUS_HANDSHAKE_SECONDS;
	rpclog("net_quic: connecting to %s:%d\n", host, port);
	return 0;
}

/* ------------------------------------------------------------------------ */
/* Polling                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Hand ngtcp2 whatever UDP has arrived.
 *
 * @return 0, or -1 if the connection is finished
 */
static int
read_packets(void)
{
	uint8_t buf[2048];
	ngtcp2_path path;
	ngtcp2_pkt_info pi;
	int i;

	memset(&pi, 0, sizeof(pi));

	path.local.addr = (struct sockaddr *) &q.local_addr;
	path.local.addrlen = q.local_addrlen;
	path.remote.addr = (struct sockaddr *) &q.remote_addr;
	path.remote.addrlen = q.remote_addrlen;
	path.user_data = NULL;

	/* Bounded rather than draining: the emulator's instruction loop is
	   waiting, and whatever is left is still there next time round. */
	for (i = 0; i < 64; i++) {
		const ngtcp2_ssize n = (ngtcp2_ssize) recv(q.fd, (char *) buf,
		    sizeof(buf), 0);
		int rc;

		if (n < 0) {
			break;		/* nothing waiting */
		}

		rc = ngtcp2_conn_read_pkt(q.conn, &path, &pi, buf, (size_t) n,
		    timestamp());
		if (rc != 0) {
			rpclog("net_quic: the connection failed: %s\n",
			    ngtcp2_strerror(rc));
			return -1;
		}
	}

	return 0;
}

/**
 * Write whatever ngtcp2 owes the relay.
 *
 * Also carries the control queue: ngtcp2 asks for stream data when it has room
 * rather than being handed it, so the queue is offered on each pass.
 *
 * @return 0, or -1 if the connection is finished
 */
static int
write_packets(void)
{
	uint8_t buf[NEXUS_QUIC_PACKET_SIZE];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	int i;

	ngtcp2_path_storage_zero(&ps);

	for (i = 0; i < 64; i++) {
		ngtcp2_vec vec;
		ngtcp2_ssize written;
		ngtcp2_ssize datalen = 0;
		const uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
		int64_t stream = -1;
		size_t vec_count = 0;

		/* The control stream, if there is anything to say and ngtcp2
		   has not already taken it.
		   No MORE flag: it means "I have further data, keep this
		   packet open", and answering it requires sending the packet
		   ngtcp2 has built so far. Coalescing one JSON line with
		   whatever follows saves nothing worth that. */
		if (q.tx_stream != -1 && q.tx_queue_sent < q.tx_queue_len) {
			vec.base = q.tx_queue + q.tx_queue_sent;
			vec.len = q.tx_queue_len - q.tx_queue_sent;
			vec_count = 1;
			stream = q.tx_stream;
		}

		written = ngtcp2_conn_writev_stream(q.conn, &ps.path, &pi, buf,
		    sizeof(buf), &datalen, flags, stream,
		    vec_count ? &vec : NULL, vec_count, timestamp());

		if (written < 0) {
			rpclog("net_quic: cannot write: %s\n",
			    ngtcp2_strerror((int) written));
			return -1;
		}
		if (written == 0) {
			break;		/* nothing more owed */
		}

		if (datalen > 0) {
			q.tx_queue_sent += (size_t) datalen;
		}

		if (send(q.fd, (const char *) buf, (size_t) written, 0) < 0) {
			/* A UDP send failing is usually transient - the route
			   is not up yet, or the buffer is full. QUIC will
			   retransmit. */
			break;
		}
	}

	/* Compact once the queue has been handed over entirely. */
	if (q.tx_queue_sent > 0 && q.tx_queue_sent == q.tx_queue_len) {
		q.tx_queue_len = 0;
		q.tx_queue_sent = 0;
	}

	return 0;
}

int
net_quic_poll(void)
{
	const int before = 0;

	if (q.conn == NULL) {
		return 0;
	}

	if (read_packets() != 0) {
		net_quic_close();
		q.want_connection = 1;
		return 0;
	}

	/* QUIC's timers: loss detection, ACK delay and the handshake all need
	   servicing at times the library chooses. The emulator polls far more
	   often than that, so asking on every pass is enough and costs a
	   comparison. */
	{
		const ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(q.conn);
		const ngtcp2_tstamp now = timestamp();

		if (expiry != UINT64_MAX && now >= expiry) {
			const int rc = ngtcp2_conn_handle_expiry(q.conn, now);

			if (rc != 0) {
				rpclog("net_quic: connection timed out: %s\n",
				    ngtcp2_strerror(rc));
				net_quic_close();
				q.want_connection = 1;
				return 0;
			}
		}
	}

	/* Our half of the control stream, opened as soon as the handshake
	   allows. The relay adopts the first bidirectional stream we open and
	   reads everything else on it. */
	if (q.handshake_done && q.tx_stream == -1) {
		if (ngtcp2_conn_open_bidi_stream(q.conn, &q.tx_stream, NULL) != 0) {
			q.tx_stream = -1;
		}
	}

	if (write_packets() != 0) {
		net_quic_close();
		q.want_connection = 1;
		return 0;
	}

	/* Frames are delivered from the datagram callback as they arrive, so
	   there is no count to accumulate here. */
	return before;
}
