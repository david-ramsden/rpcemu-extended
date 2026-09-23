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
 * nexus_enrol - giving a machine an identity on Nexus.
 *
 * The user gets a token from the web site and pastes it in. This makes a key,
 * asks Nexus to certify it, and leaves three files in the machine's own
 * directory:
 *
 *     nexus.key   this machine's private key
 *     nexus.crt   the certificate Nexus issued for it
 *     nexus-ca.crt  the authority that signed both that and the relay's
 *
 * ★ THE KEY IS MADE HERE AND NEVER LEAVES.
 *
 * What travels is a certificate signing request: the public half and a
 * signature proving we hold the private half. Nexus never sees the key, cannot
 * be made to reveal it, and a copy of its database does not let anybody be
 * this machine. That is the whole reason enrolment is a token and a CSR rather
 * than a download.
 *
 * The CA arrives with the certificate rather than being shipped with RPCEmu.
 * It is what the relay's own certificate is checked against, so having it come
 * from the same call means it can be rotated without a release.
 */

#ifndef NEXUS_ENROL_H
#define NEXUS_ENROL_H

#include <wx/string.h>

/** Where a machine's enrolment is kept, and whether it has one. */
struct NexusEnrolment {
	wxString	ca_path;
	wxString	cert_path;
	wxString	key_path;

	/** All three files are present. */
	bool		complete = false;
};

/**
 * Where this machine's enrolment would be, present or not.
 *
 * @param machine_dir The machine's own directory
 */
NexusEnrolment NexusEnrolmentFor(const wxString &machine_dir);

/**
 * Enrol a machine: make a key, have it certified, and write the three files.
 *
 * Replaces any existing enrolment, which is what re-enrolling means - the old
 * certificate stops working as soon as Nexus issues a new one, so leaving the
 * old files in place would only leave something that cannot connect.
 *
 * @param machine_dir Where to put the files
 * @param token       What the user pasted, from the web site
 * @param mac         The machine's MAC address; the relay refuses frames from
 *                    any other, so the two have to be the same one
 * @param error       Set to something worth showing the user on failure
 * @return            true if the machine is now enrolled
 */
bool NexusEnrol(const wxString &machine_dir, const wxString &token,
    const wxString &mac, wxString &error);

#endif /* NEXUS_ENROL_H */
