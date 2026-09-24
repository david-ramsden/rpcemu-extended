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
 * nexus_renew - keeping a machine's certificate current.
 *
 * A certificate lasts ninety days and may be renewed from the forty-fifth.
 * Renewal is enrolment with a different proof of identity: the same key and
 * signing request, presented over a connection authenticated with the
 * certificate being replaced rather than with a token from the web site. The
 * user is not involved, which is the point - ninety days is about how long a
 * machine may sit switched off, not about how often somebody does something.
 *
 * ★ CALLED FROM EVERY PATH THAT STARTS A MACHINE.
 *
 * There are three: the Manager, --machine without it, and --headless. Only the
 * first has a Manager to schedule anything, and only the first two have wx at
 * all. A machine configured once through the Manager and run headless from
 * then on is the case most likely to matter - it is the one somebody depends
 * on remotely - so this is a plain function with no interface, called beside
 * SupportFilesEnsure() in each of them.
 *
 * It is not called from net_quic_init(): that runs on the emulator thread
 * while the machine is starting, and this blocks.
 *
 * ★ NOT wxWebRequest, AND NOT curl.
 *
 * wxWebRequest cannot present a client certificate - its whole TLS surface is
 * DisablePeerVerify(), which is about verifying the server. curl could, but we
 * do not link it: a Nexus build links ngtcp2 and wolfSSL, and adding curl
 * would mean a second TLS stack in the same process on Linux, a new dependency
 * in the Windows cross-build, and another MacPorts port to verify on two
 * architectures.
 *
 * So this speaks HTTP over wolfSSL, which is already here and already holds
 * the machine's key. That is normally a mistake; it is justified by how narrow
 * the request is - one POST to a server we control, no redirects, no cookies,
 * no proxies, no chunked encoding. If it ever grows those, this decision was
 * wrong and wants revisiting rather than extending.
 */

#ifndef NEXUS_RENEW_H
#define NEXUS_RENEW_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Nexus itself, which is not the relay.
 *
 * The relay carries frames; this is the web application that issues
 * certificates. Different host, different protocol, different port.
 *
 * RPCEMU_NEXUS_API overrides it, as a whole base URL, for developing against
 * one of your own - the same idea as RPCEMU_NEXUS_RELAY. nexus_enrol.cpp reads
 * the same variable.
 */
#define NEXUS_API_HOST	"nexus.branchthroughzero.co.uk"
#define NEXUS_API_PORT	443
#define NEXUS_RENEW_DAYS	45

/** What a renewal attempt did. */
enum nexus_renew_result {
	NEXUS_RENEW_NOT_DUE,	/**< Still well inside its dates. */
	NEXUS_RENEW_DONE,	/**< A new certificate is on disc. */
	NEXUS_RENEW_FAILED,	/**< Nexus could not be reached, or refused. */
	NEXUS_RENEW_EXPIRED,	/**< Too late: only a fresh token helps now. */
	NEXUS_RENEW_NOT_ENROLLED, /**< Nothing to renew. */
};

/**
 * Renew this machine's certificate if it is old enough to need it.
 *
 * Reads the certificate, and does nothing at all unless it is within
 * NEXUS_RENEW_DAYS of running out - so calling this on every start costs one
 * file read almost every time.
 *
 * Blocking, with a short timeout and no retry: there are forty-five days of
 * runway, and a machine must never fail to start because Nexus was slow.
 *
 * Writes through a temporary file and renames, so an interruption leaves the
 * old enrolment intact. That matters more than it looks: Nexus moves the
 * machine's serial on as soon as it signs, so a renewal that is issued and not
 * saved leaves a machine that still reaches the relay - the relay checks the
 * CA and the dates, not the serial - but can never renew again, and says
 * nothing until it expires.
 *
 * @param machine_datadir The machine's own directory, ending in a separator
 * @return                what happened; every case is logged
 */
extern enum nexus_renew_result nexus_renew_if_due(const char *machine_datadir);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_RENEW_H */
