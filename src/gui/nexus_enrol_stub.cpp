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
 * nexus_enrol, for a build without the QUIC libraries.
 *
 * Enrolment makes a key and a certificate request, which is wolfSSL's work, and
 * the certificate it produces is only good for a wire this build does not have.
 * So the settings still show the box - a machine can be enrolled and the files
 * are still there - and enrolling says why it cannot be done here rather than
 * failing obscurely.
 *
 * Built instead of nexus_enrol.cpp, never alongside it.
 */

#include "nexus_enrol.h"

#include <wx/filefn.h>
#include <wx/filename.h>

NexusEnrolment NexusEnrolmentFor(const wxString &machine_dir)
{
	NexusEnrolment e;
	const wxString sep = wxFileName::GetPathSeparator();

	/* The same paths the real one uses: a machine enrolled by a build with
	   Nexus is still enrolled when opened by one without, and saying so is
	   more use than pretending it is not. */
	e.ca_path = machine_dir + sep + "nexus-ca.crt";
	e.cert_path = machine_dir + sep + "nexus.crt";
	e.key_path = machine_dir + sep + "nexus.key";

	/* Valid rather than a state of its own, and the dates left unset.
	   Parsing the certificate is wolfSSL's work and this build has none, so
	   the expiry is a thing it cannot know - and a build that cannot connect
	   either way has no use for it. What the settings need from here is that
	   the machine is enrolled, which the files answer. */
	e.state = (wxFileExists(e.ca_path) && wxFileExists(e.cert_path) &&
	    wxFileExists(e.key_path)) ? NexusState::Valid : NexusState::NotEnrolled;

	return e;
}

bool NexusEnrol(wxWindow *parent, const wxString &machine_dir,
    const wxString &token, const wxString &mac, wxString &error)
{
	(void) parent;
	(void) machine_dir;
	(void) token;
	(void) mac;

	error = "This build of RPCEmu was made without Nexus support, so it "
	        "cannot enrol a machine or join the network.\n\n"
	        "Nexus needs ngtcp2 and wolfSSL, which no package manager "
	        "provides in the form it wants; build-quic-libs.sh builds them, "
	        "and the build then has to be configured with "
	        "-DRPCEMU_ENABLE_NEXUS=ON.";
	return false;
}
