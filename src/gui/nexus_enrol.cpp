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
 * nexus_enrol - see nexus_enrol.h for what enrolment is and why the key is
 * made here.
 */

#include "nexus_enrol.h"

#include <wx/filefn.h>
#include <wx/filename.h>
#include <wx/textfile.h>
#include <wx/wfstream.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include "http_transfer.h"

extern "C" {
#include "net_quic.h"
#include "rpcemu.h"
}

/*
 * Where Nexus lives. The relay is in net_quic.h because the wire needs it;
 * this is the web application, which is a different host doing a different
 * job, and only enrolment talks to it.
 *
 * RPCEMU_NEXUS_API overrides it for developing against one of your own, the
 * way RPCEMU_NEXUS_RELAY does for the relay.
 */
#define NEXUS_API_BASE	"https://nexus.branchthroughzero.co.uk"

namespace {

wxString ApiBase()
{
	const char *override_url = getenv("RPCEMU_NEXUS_API");

	if (override_url != nullptr && override_url[0] != '\0') {
		return wxString::FromUTF8(override_url);
	}
	return NEXUS_API_BASE;
}

/** A reporter for Transfer, which wants one and has nothing to report to. */
class SilentReporter : public RiscosFetchReporter {
public:
	bool Stage(const wxString &) override { return true; }
	bool Progress(long long, long long) override { return true; }
};

/**
 * One top-level string out of a JSON object.
 *
 * Nexus answers with a flat object of known shape, written by one program, so
 * a parser would be a dependency bought for nothing. It handles the escapes
 * that actually appear: a PEM certificate arrives as one string with \n in it.
 */
wxString JsonString(const wxString &json, const wxString &key)
{
	const wxString needle = "\"" + key + "\"";
	int at = json.Find(needle);

	if (at == wxNOT_FOUND) {
		return wxEmptyString;
	}

	size_t i = static_cast<size_t>(at) + needle.length();

	while (i < json.length() && (json[i] == ' ' || json[i] == ':')) {
		i++;
	}
	if (i >= json.length() || json[i] != '"') {
		return wxEmptyString;
	}
	i++;

	wxString out;

	while (i < json.length() && json[i] != '"') {
		if (json[i] == '\\' && i + 1 < json.length()) {
			i++;
			switch (static_cast<char>(json[i])) {
			case 'n': out += '\n'; break;
			case 'r': out += '\r'; break;
			case 't': out += '\t'; break;
			case '/': out += '/'; break;
			default:  out += json[i]; break;
			}
		} else {
			out += json[i];
		}
		i++;
	}

	return out;
}

/** A PEM file, written so only this user can read it. */
bool WritePem(const wxString &path, const wxString &pem, wxString &error)
{
	wxFileOutputStream out(path);

	if (!out.IsOk()) {
		error = wxString::Format("Could not write %s.", path);
		return false;
	}

	const wxScopedCharBuffer utf8 = pem.utf8_str();

	out.WriteAll(utf8.data(), utf8.length());
	if (!out.IsOk()) {
		error = wxString::Format("Could not write %s.", path);
		return false;
	}
	out.Close();

	/* The key especially: it is the machine's identity, and a file left
	   world-readable is one an unrelated program can copy. */
	wxFileName(path).SetPermissions(wxPOSIX_USER_READ | wxPOSIX_USER_WRITE);
	return true;
}

/**
 * A P-256 key and a certificate signing request for it.
 *
 * @param key_pem Set to the private key, which stays here
 * @param csr_pem Set to the request, which is what travels
 */
bool MakeKeyAndRequest(wxString &key_pem, wxString &csr_pem, wxString &error)
{
	WC_RNG rng;
	ecc_key key;
	Cert req;
	byte der[4096];
	byte pem[4096];
	byte key_der[1024];
	byte key_pem_buf[2048];
	int rc;

	if (wc_InitRng(&rng) != 0) {
		error = "Could not start the random number generator.";
		return false;
	}
	if (wc_ecc_init(&key) != 0) {
		wc_FreeRng(&rng);
		error = "Could not prepare a key.";
		return false;
	}

	/* P-256, which is what Nexus certifies and what the relay's TLS
	   expects. 32 bytes is that curve's key size. */
	if (wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1) != 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not generate a key.";
		return false;
	}

	rc = wc_EccKeyToDer(&key, key_der, sizeof(key_der));
	if (rc < 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not encode the key.";
		return false;
	}
	rc = wc_DerToPem(key_der, static_cast<word32>(rc), key_pem_buf,
	    sizeof(key_pem_buf), ECC_PRIVATEKEY_TYPE);
	if (rc < 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not encode the key.";
		return false;
	}
	key_pem = wxString::From8BitData(reinterpret_cast<const char *>(key_pem_buf),
	    static_cast<size_t>(rc));

	if (wc_InitCert(&req) != 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not prepare the request.";
		return false;
	}

	/* The subject is not what identifies the machine - Nexus puts its own
	   identifier in the certificate it issues, from the token - so this is
	   only something for a human reading the request. */
	strncpy(req.subject.commonName, "RPCEmu Extended", CTC_NAME_SIZE - 1);
	req.sigType = CTC_SHA256wECDSA;

	rc = wc_MakeCertReq(&req, der, sizeof(der), nullptr, &key);
	if (rc < 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not build the request.";
		return false;
	}

	rc = wc_SignCert(req.bodySz, req.sigType, der, sizeof(der), nullptr, &key, &rng);
	if (rc < 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not sign the request.";
		return false;
	}

	rc = wc_DerToPem(der, static_cast<word32>(rc), pem, sizeof(pem), CERTREQ_TYPE);
	if (rc < 0) {
		wc_ecc_free(&key);
		wc_FreeRng(&rng);
		error = "Could not encode the request.";
		return false;
	}
	csr_pem = wxString::From8BitData(reinterpret_cast<const char *>(pem),
	    static_cast<size_t>(rc));

	wc_ecc_free(&key);
	wc_FreeRng(&rng);
	return true;
}

/** A string as a JSON value, with the characters that would break one escaped. */
wxString JsonEscape(const wxString &s)
{
	wxString out;

	for (size_t i = 0; i < s.length(); i++) {
		switch (static_cast<char>(s[i])) {
		case '"':  out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default:   out += s[i]; break;
		}
	}
	return out;
}

} /* namespace */

NexusEnrolment NexusEnrolmentFor(const wxString &machine_dir)
{
	NexusEnrolment e;
	const wxString sep = wxFileName::GetPathSeparator();

	e.ca_path = machine_dir + sep + "nexus-ca.crt";
	e.cert_path = machine_dir + sep + "nexus.crt";
	e.key_path = machine_dir + sep + "nexus.key";
	e.complete = wxFileExists(e.ca_path) && wxFileExists(e.cert_path) &&
	    wxFileExists(e.key_path);

	return e;
}

bool NexusEnrol(const wxString &machine_dir, const wxString &token,
    const wxString &mac, wxString &error)
{
	wxString key_pem;
	wxString csr_pem;

	if (token.Strip(wxString::both).empty()) {
		error = "Paste the enrolment token from the Nexus web site first.";
		return false;
	}
	if (mac.empty()) {
		error = "This machine has no MAC address, which Nexus needs to know.";
		return false;
	}

	if (!MakeKeyAndRequest(key_pem, csr_pem, error)) {
		return false;
	}

	SilentReporter reporter;
	Transfer transfer(reporter, "Enrolling", RiscosFetchLoopFactory());

	const wxString body = wxString::Format(
	    "{\"token\": \"%s\", \"csr\": \"%s\", \"mac\": \"%s\"}",
	    JsonEscape(token.Strip(wxString::both)),
	    JsonEscape(csr_pem),
	    JsonEscape(mac));

	if (!transfer.PostJson(ApiBase() + "/api/v1/enrol", body)) {
		/* Nexus explains a refusal in the body, and that sentence is
		   written for the person reading it - "That enrolment token is
		   not usable. Ask for another one." says more than a status. */
		const wxString said = JsonString(transfer.Body(), "error");

		error = said.empty() ? transfer.Error() : said;
		return false;
	}

	{
		const wxString cert = JsonString(transfer.Body(), "certificate");
		const wxString ca = JsonString(transfer.Body(), "ca");
		const NexusEnrolment e = NexusEnrolmentFor(machine_dir);

		if (cert.empty() || ca.empty()) {
			error = "Nexus did not send a certificate.";
			return false;
		}

		/* The key last. The other two are useless without it, so a
		   failure part way through leaves a machine that is plainly not
		   enrolled rather than one that looks enrolled and cannot
		   connect. */
		if (!WritePem(e.ca_path, ca, error) ||
		    !WritePem(e.cert_path, cert, error) ||
		    !WritePem(e.key_path, key_pem, error)) {
			return false;
		}
	}

	return true;
}
