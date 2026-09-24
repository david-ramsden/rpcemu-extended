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
 * net_quic, for a build without ngtcp2 and wolfSSL.
 *
 * The Nexus wire needs two libraries no package manager ships in the form it
 * wants, so a build has to be able to do without them. These answer the way a
 * machine with no relay configured does, which network-nat.c already handles:
 * it moves on to the next wire.
 *
 * Built instead of net_quic.c, never alongside it.
 */

#include <stdint.h>

#include "net_quic.h"
#include "nexus_renew.h"

int
net_quic_init(void)
{
	return -1;
}

int
net_quic_connect(const char *host, int port, const char *ca_file,
    const char *cert_file, const char *key_file)
{
	(void) host;
	(void) port;
	(void) ca_file;
	(void) cert_file;
	(void) key_file;
	return -1;
}

void
net_quic_close(void)
{
}

int
net_quic_is_connected(void)
{
	return 0;
}

int
net_quic_wants_connection(void)
{
	return 0;
}

void
net_quic_tx(const uint8_t *frame, int frame_len)
{
	(void) frame;
	(void) frame_len;
}

int
net_quic_poll(void)
{
	return 0;
}

/*
 * Renewal, which needs wolfSSL to build a signing request and to speak TLS.
 * A build without it cannot join Nexus either, so there is nothing to keep
 * current.
 */
enum nexus_renew_result
nexus_renew_if_due(const char *machine_datadir)
{
	(void) machine_datadir;

	return NEXUS_RENEW_NOT_ENROLLED;
}
