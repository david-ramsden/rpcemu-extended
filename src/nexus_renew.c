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
 * nexus_renew - see nexus_renew.h for why this speaks HTTP itself.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#ifndef _WIN32
#include <sys/types.h>
#endif

#include "socket-compat.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include "nexus_renew.h"
#include "rpcemu.h"

/*
 * How long to wait on the whole exchange.
 *
 * Short deliberately. Renewal begins forty-five days before it matters, so
 * there is no call to make anybody wait: a machine that cannot reach Nexus
 * this time tries again next start.
 */
#define RENEW_TIMEOUT_MS	5000

/* A certificate and a key are around a kilobyte of PEM each; the reply carries
   two of them and a little JSON. */
#define PEM_MAX			8192
#define REPLY_MAX		16384

/**
 * Where Nexus is, and whether to check who answers.
 */
struct api_target {
	char	host[256];
	int	port;
	int	insecure;
};

/**
 * Read the base URL, honouring RPCEMU_NEXUS_API.
 *
 * Accepts "https://host", "https://host:port" and a bare "host:port", which is
 * what somebody testing against a local stack is likely to type.
 */
static void
api_target(struct api_target *t)
{
	const char *override = getenv("RPCEMU_NEXUS_API");
	const char *insecure = getenv("RPCEMU_NEXUS_API_INSECURE");
	const char *at;
	const char *colon;

	snprintf(t->host, sizeof(t->host), "%s", NEXUS_API_HOST);
	t->port = NEXUS_API_PORT;
	t->insecure = 0;

	if (override == NULL || override[0] == '\0') {
		return;
	}

	at = override;
	if (strncmp(at, "https://", 8) == 0) {
		at += 8;
	} else if (strncmp(at, "http://", 7) == 0) {
		/* Renewal presents a client certificate, which needs TLS. There
		   is nothing to fall back to, so this is refused rather than
		   silently upgraded. */
		rpclog("nexus_renew: RPCEMU_NEXUS_API is http://, which cannot "
		       "carry a client certificate; using %s instead\n",
		    NEXUS_API_HOST);
		return;
	}

	colon = strrchr(at, ':');
	if (colon != NULL && colon[1] != '\0') {
		const size_t len = (size_t) (colon - at);

		if (len > 0 && len < sizeof(t->host)) {
			memcpy(t->host, at, len);
			t->host[len] = '\0';
			t->port = atoi(colon + 1);
		}
	} else {
		size_t len = strlen(at);

		/* A trailing slash is natural to type and is not part of the
		   host name. */
		while (len > 0 && at[len - 1] == '/') {
			len--;
		}
		if (len > 0 && len < sizeof(t->host)) {
			memcpy(t->host, at, len);
			t->host[len] = '\0';
		}
	}

	if (insecure != NULL && insecure[0] != '\0' && insecure[0] != '0') {
		t->insecure = 1;
	}

	rpclog("nexus_renew: RPCEMU_NEXUS_API is set, so renewing against %s:%d\n",
	    t->host, t->port);
}

/**
 * A whole file, as a NUL-terminated string.
 *
 * @return the length, or -1
 */
static int
read_file(const char *path, char *buf, size_t buf_len)
{
	FILE *f = fopen(path, "rb");
	size_t got;

	if (f == NULL) {
		return -1;
	}

	got = fread(buf, 1, buf_len - 1, f);
	fclose(f);

	if (got == 0) {
		return -1;
	}
	buf[got] = '\0';
	return (int) got;
}

/**
 * A file written so that only this user can read it, through a temporary name.
 *
 * The rename is what makes an interrupted renewal harmless: the old file is
 * either wholly replaced or wholly untouched, never half-written.
 *
 * @return 0, or -1 with the reason logged
 */
static int
write_file_atomically(const char *path, const char *data, size_t len, int private_)
{
	char tmp[600];
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.new", path);

	f = fopen(tmp, "wb");
	if (f == NULL) {
		rpclog("nexus_renew: cannot write %s\n", tmp);
		return -1;
	}
	if (fwrite(data, 1, len, f) != len) {
		rpclog("nexus_renew: cannot write %s\n", tmp);
		fclose(f);
		remove(tmp);
		return -1;
	}
	if (fclose(f) != 0) {
		rpclog("nexus_renew: cannot write %s\n", tmp);
		remove(tmp);
		return -1;
	}

#ifdef _WIN32
	/* Windows will not rename onto an existing file. */
	remove(path);
#endif
	if (rename(tmp, path) != 0) {
		rpclog("nexus_renew: cannot replace %s\n", path);
		remove(tmp);
		return -1;
	}

	/* The key is the machine's identity, and one left world-readable is one
	   an unrelated program can copy. The certificates are public. */
#ifndef _WIN32
	chmod(path, private_ ? (S_IRUSR | S_IWUSR)
	                     : (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
#endif
	return 0;
}

/**
 * When the certificate in this file runs out.
 *
 * @param path      The PEM file
 * @param not_after Set to its notAfter as a time_t, in UTC
 * @return          0, or -1
 */
static int
certificate_expiry(const char *path, time_t *not_after)
{
	char pem[PEM_MAX];
	byte der[PEM_MAX];
	DecodedCert cert;
	int pem_len;
	int der_len;
	int rc = -1;

	pem_len = read_file(path, pem, sizeof(pem));
	if (pem_len < 0) {
		return -1;
	}

	der_len = wc_CertPemToDer((const byte *) pem, pem_len, der, sizeof(der),
	    CERT_TYPE);
	if (der_len < 0) {
		return -1;
	}

	wc_InitDecodedCert(&cert, der, (word32) der_len, NULL);

	/* NO_VERIFY: the signature is the relay's business, and it has the CA
	   to check it against. This wants the dates out of a file we wrote. */
	if (wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL) == 0 &&
	    cert.afterDate != NULL && cert.afterDateLen > 0) {
		const byte *date = NULL;
		byte format = 0;
		int len = 0;

		if (wc_GetDateInfo(cert.afterDate, cert.afterDateLen, &date,
		        &format, &len) == 0) {
			struct tm when;

			memset(&when, 0, sizeof(when));
			if (wc_GetDateAsCalendarTime(date, len, format, &when) == 0) {
				/* timegm() reads it as UTC, which is what a
				   certificate's dates are. Windows spells it
				   _mkgmtime. */
#ifdef _WIN32
				*not_after = _mkgmtime(&when);
#else
				*not_after = timegm(&when);
#endif
				rc = (*not_after == (time_t) -1) ? -1 : 0;
			}
		}
	}

	wc_FreeDecodedCert(&cert);
	return rc;
}

/**
 * A P-256 key and a signing request for it.
 *
 * The same shape as enrolment's: the key is made here and never leaves, and
 * what travels is the public half with a signature proving we hold the other.
 * Renewal replaces the key as well as the certificate.
 *
 * @return 0, or -1 with the reason logged
 */
static int
make_key_and_request(char *key_pem, size_t key_pem_len, char *csr_pem,
    size_t csr_pem_len)
{
	WC_RNG rng;
	ecc_key key;
	Cert *req = NULL;
	byte *der = NULL;
	byte *key_der = NULL;
	int rc = -1;
	int len;

	if (wc_InitRng(&rng) != 0) {
		rpclog("nexus_renew: no random number generator\n");
		return -1;
	}
	if (wc_ecc_init(&key) != 0) {
		wc_FreeRng(&rng);
		rpclog("nexus_renew: cannot prepare a key\n");
		return -1;
	}

	/* Cert is around 25KB, which is too much for some of the stacks this
	   runs on. */
	req = malloc(sizeof(*req));
	der = malloc(PEM_MAX);
	key_der = malloc(PEM_MAX);

	if (req == NULL || der == NULL || key_der == NULL) {
		goto out;
	}

	if (wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1) != 0) {
		rpclog("nexus_renew: cannot generate a key\n");
		goto out;
	}

	len = wc_EccKeyToDer(&key, key_der, PEM_MAX);
	if (len < 0) {
		goto out;
	}
	len = wc_DerToPem(key_der, (word32) len, (byte *) key_pem,
	    (word32) key_pem_len, ECC_PRIVATEKEY_TYPE);
	if (len < 0 || (size_t) len >= key_pem_len) {
		goto out;
	}
	key_pem[len] = '\0';

	if (wc_InitCert(req) != 0) {
		goto out;
	}

	/* Nexus puts its own identifier in what it issues, so the subject is
	   only something for a human reading the request. */
	strncpy(req->subject.commonName, "RPCEmu Extended", CTC_NAME_SIZE - 1);
	req->sigType = CTC_SHA256wECDSA;

	len = wc_MakeCertReq(req, der, PEM_MAX, NULL, &key);
	if (len < 0) {
		goto out;
	}
	len = wc_SignCert(req->bodySz, req->sigType, der, PEM_MAX, NULL, &key, &rng);
	if (len < 0) {
		goto out;
	}
	len = wc_DerToPem(der, (word32) len, (byte *) csr_pem,
	    (word32) csr_pem_len, CERTREQ_TYPE);
	if (len < 0 || (size_t) len >= csr_pem_len) {
		goto out;
	}
	csr_pem[len] = '\0';
	rc = 0;

out:
	if (rc != 0) {
		rpclog("nexus_renew: cannot build a signing request\n");
	}
	free(req);
	free(der);
	free(key_der);
	wc_ecc_free(&key);
	wc_FreeRng(&rng);
	return rc;
}

/**
 * Connect, with the timeout applying to the connect itself.
 *
 * @return the socket, or -1
 */
static int
connect_to(const char *host, int port)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char service[16];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(service, sizeof(service), "%d", port);

	if (getaddrinfo(host, service, &hints, &res) != 0) {
		rpclog("nexus_renew: cannot resolve %s\n", host);
		return -1;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = (int) socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		if (connect(fd, ai->ai_addr, (socklen_t) ai->ai_addrlen) == 0) {
			break;
		}
		closesocket(fd);
		fd = -1;
	}

	freeaddrinfo(res);

	if (fd < 0) {
		rpclog("nexus_renew: cannot reach %s:%d\n", host, port);
	}
	return fd;
}

/**
 * Set both directions' timeouts, so a stalled server cannot hold up a start.
 */
static void
set_socket_timeout(int fd, int ms)
{
#ifdef _WIN32
	DWORD tv = (DWORD) ms;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &tv, sizeof(tv));
#else
	struct timeval tv;

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

/**
 * One string out of a flat JSON object.
 *
 * Nexus answers with an object of known shape written by one program, so a
 * parser would be a dependency bought for nothing. This handles the escapes
 * that actually appear: a PEM certificate arrives as one string with \n in it.
 *
 * @return 0, or -1 if the key is not there
 */
static int
json_string(const char *json, const char *key, char *out, size_t out_len)
{
	char needle[64];
	const char *at;
	size_t o = 0;

	snprintf(needle, sizeof(needle), "\"%s\"", key);
	at = strstr(json, needle);
	if (at == NULL) {
		return -1;
	}

	at += strlen(needle);
	while (*at == ' ' || *at == ':') {
		at++;
	}
	if (*at != '"') {
		return -1;
	}
	at++;

	while (*at != '\0' && *at != '"' && o + 1 < out_len) {
		if (*at == '\\' && at[1] != '\0') {
			at++;
			switch (*at) {
			case 'n': out[o++] = '\n'; break;
			case 'r': out[o++] = '\r'; break;
			case 't': out[o++] = '\t'; break;
			case '/': out[o++] = '/'; break;
			default:  out[o++] = *at; break;
			}
		} else {
			out[o++] = *at;
		}
		at++;
	}

	out[o] = '\0';
	return 0;
}

/**
 * The JSON body, with what would break one escaped.
 *
 * @return 0, or -1 if it would not fit
 */
static int
json_body(char *out, size_t out_len, const char *csr)
{
	static const char prefix[] = "{\"csr\": \"";
	static const char suffix[] = "\"}";
	size_t o = 0;
	size_t i;

	if (sizeof(prefix) - 1 >= out_len) {
		return -1;
	}
	memcpy(out, prefix, sizeof(prefix) - 1);
	o = sizeof(prefix) - 1;

	for (i = 0; csr[i] != '\0'; i++) {
		const char *escape = NULL;

		switch (csr[i]) {
		case '"':  escape = "\\\""; break;
		case '\\': escape = "\\\\"; break;
		case '\n': escape = "\\n"; break;
		case '\r': escape = "\\r"; break;
		case '\t': escape = "\\t"; break;
		default:   break;
		}

		if (escape != NULL) {
			if (o + 2 >= out_len) {
				return -1;
			}
			out[o++] = escape[0];
			out[o++] = escape[1];
		} else {
			if (o + 1 >= out_len) {
				return -1;
			}
			out[o++] = csr[i];
		}
	}

	if (o + sizeof(suffix) > out_len) {
		return -1;
	}
	memcpy(out + o, suffix, sizeof(suffix));
	return 0;
}

/**
 * POST the signing request and read what comes back.
 *
 * @param status Set to the HTTP status, or 0 if there was not one
 * @param reply  Set to the response body
 * @return       0 if a reply was read, -1 with the reason logged
 */
static int
post_renewal(const struct api_target *t, const char *ca_file,
    const char *cert_file, const char *key_file, const char *body,
    int *status, char *reply, size_t reply_len)
{
	WOLFSSL_CTX *ctx = NULL;
	WOLFSSL *ssl = NULL;
	char request[PEM_MAX * 2];
	char raw[REPLY_MAX];
	const char *headers_end;
	int fd = -1;
	int request_len;
	int got = 0;
	int rc = -1;

	*status = 0;

	ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (ctx == NULL) {
		rpclog("nexus_renew: no TLS context\n");
		return -1;
	}

	/* TLS 1.2 or better; the method above is a floor, not a ceiling. */
	wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);

	if (t->insecure) {
		/* Said on every renewal it affects, not once at startup: this
		   is the only way verification is ever off, and a machine
		   quietly renewing over an unverified connection for months is
		   the thing to prevent. */
		rpclog("nexus_renew: RPCEMU_NEXUS_API_INSECURE is set, so NOT "
		       "checking who answers at %s - for testing only\n", t->host);
		wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
	} else {
		/* The system's trust store, not the enrolment CA: Nexus is a
		   public web site with an ordinary certificate, where the relay
		   is ours and pinned. */
		if (wolfSSL_CTX_load_system_CA_certs(ctx) != WOLFSSL_SUCCESS) {
			rpclog("nexus_renew: cannot read the system certificate store\n");
			goto out;
		}
		wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
	}

	(void) ca_file;

	/* Ours, which is how Nexus knows which machine is asking. */
	if (wolfSSL_CTX_use_certificate_chain_file(ctx, cert_file) != WOLFSSL_SUCCESS) {
		rpclog("nexus_renew: cannot read the machine certificate %s\n", cert_file);
		goto out;
	}
	if (wolfSSL_CTX_use_PrivateKey_file(ctx, key_file,
	        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
		rpclog("nexus_renew: cannot read the machine key %s\n", key_file);
		goto out;
	}

	fd = connect_to(t->host, t->port);
	if (fd < 0) {
		goto out;
	}
	set_socket_timeout(fd, RENEW_TIMEOUT_MS);

	ssl = wolfSSL_new(ctx);
	if (ssl == NULL) {
		rpclog("nexus_renew: no TLS session\n");
		goto out;
	}
	wolfSSL_set_fd(ssl, fd);

	/* Without SNI a host sharing an address answers as somebody else. */
	wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, t->host,
	    (unsigned short) strlen(t->host));
	if (!t->insecure) {
		wolfSSL_check_domain_name(ssl, t->host);
	}

	if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
		char reason[80];
		const int err = wolfSSL_get_error(ssl, 0);

		wolfSSL_ERR_error_string((unsigned long) err, reason);
		rpclog("nexus_renew: TLS to %s failed: %s\n", t->host, reason);
		goto out;
	}

	request_len = snprintf(request, sizeof(request),
	    "POST /api/v1/renew HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "User-Agent: RPCEmu Spork Edition/%s\r\n"
	    "Content-Type: application/json\r\n"
	    "Content-Length: %u\r\n"
	    "Connection: close\r\n"
	    "\r\n"
	    "%s",
	    t->host, VERSION, (unsigned) strlen(body), body);

	if (request_len < 0 || (size_t) request_len >= sizeof(request)) {
		rpclog("nexus_renew: the signing request is too large to send\n");
		goto out;
	}

	if (wolfSSL_write(ssl, request, request_len) != request_len) {
		rpclog("nexus_renew: could not send the renewal request\n");
		goto out;
	}

	/* Connection: close, so the read ends at end of stream and there is no
	   need to understand keep-alive or chunked framing. */
	for (;;) {
		const int n = wolfSSL_read(ssl, raw + got,
		    (int) (sizeof(raw) - 1 - (size_t) got));

		if (n <= 0) {
			break;
		}
		got += n;
		if ((size_t) got >= sizeof(raw) - 1) {
			break;
		}
	}
	raw[got] = '\0';

	if (got == 0) {
		rpclog("nexus_renew: Nexus said nothing\n");
		goto out;
	}

	if (sscanf(raw, "HTTP/1.%*d %d", status) != 1) {
		rpclog("nexus_renew: Nexus did not answer with HTTP\n");
		goto out;
	}

	headers_end = strstr(raw, "\r\n\r\n");
	if (headers_end == NULL) {
		rpclog("nexus_renew: Nexus sent no body\n");
		goto out;
	}
	snprintf(reply, reply_len, "%s", headers_end + 4);
	rc = 0;

out:
	if (ssl != NULL) {
		wolfSSL_shutdown(ssl);
		wolfSSL_free(ssl);
	}
	if (fd >= 0) {
		closesocket(fd);
	}
	wolfSSL_CTX_free(ctx);
	return rc;
}

enum nexus_renew_result
nexus_renew_if_due(const char *machine_datadir)
{
	struct api_target target;
	char ca_path[512], cert_path[512], key_path[512];
	char key_pem[PEM_MAX], csr_pem[PEM_MAX];
	char body[PEM_MAX * 2];
	char reply[REPLY_MAX];
	char certificate[PEM_MAX], authority[PEM_MAX];
	time_t not_after;
	time_t now;
	int status = 0;

	if (machine_datadir == NULL || machine_datadir[0] == '\0') {
		return NEXUS_RENEW_NOT_ENROLLED;
	}

	/* datadir ends in a separator already. */
	snprintf(ca_path, sizeof(ca_path), "%snexus-ca.crt", machine_datadir);
	snprintf(cert_path, sizeof(cert_path), "%snexus.crt", machine_datadir);
	snprintf(key_path, sizeof(key_path), "%snexus.key", machine_datadir);

	if (certificate_expiry(cert_path, &not_after) != 0) {
		return NEXUS_RENEW_NOT_ENROLLED;
	}

	now = time(NULL);

	if (now >= not_after) {
		/* Nexus refuses to renew a certificate that has run out, so
		   there is nothing to try. */
		rpclog("nexus_renew: this machine's certificate expired; it "
		       "needs enrolling again\n");
		return NEXUS_RENEW_EXPIRED;
	}

	if (now < not_after - (time_t) NEXUS_RENEW_DAYS * 24 * 60 * 60) {
		return NEXUS_RENEW_NOT_DUE;
	}

	rpclog("nexus_renew: this machine's certificate is due for renewal\n");

	api_target(&target);

	if (make_key_and_request(key_pem, sizeof(key_pem), csr_pem,
	        sizeof(csr_pem)) != 0) {
		return NEXUS_RENEW_FAILED;
	}
	if (json_body(body, sizeof(body), csr_pem) != 0) {
		rpclog("nexus_renew: the signing request is too large to send\n");
		return NEXUS_RENEW_FAILED;
	}

	if (post_renewal(&target, ca_path, cert_path, key_path, body, &status,
	        reply, sizeof(reply)) != 0) {
		return NEXUS_RENEW_FAILED;
	}

	if (status != 200) {
		char said[256];

		if (json_string(reply, "error", said, sizeof(said)) == 0) {
			rpclog("nexus_renew: Nexus refused: %s\n", said);
		} else {
			rpclog("nexus_renew: Nexus answered %d\n", status);
		}
		return NEXUS_RENEW_FAILED;
	}

	if (json_string(reply, "certificate", certificate, sizeof(certificate)) != 0 ||
	    json_string(reply, "ca", authority, sizeof(authority)) != 0) {
		rpclog("nexus_renew: Nexus sent no certificate\n");
		return NEXUS_RENEW_FAILED;
	}

	/*
	 * ★ THE OLD CERTIFICATE IS ALREADY DEAD BY HERE.
	 *
	 * Nexus moved this machine's serial on when it signed, so what is on
	 * disc no longer identifies it. Failing to write now leaves a machine
	 * that still reaches the relay - which checks the CA and the dates, not
	 * the serial - but can never renew again, and says nothing until it
	 * expires. Each file is written whole or not at all, and the key goes
	 * last so a failure part way leaves a machine that is plainly broken
	 * rather than one that looks enrolled and is not.
	 */
	if (write_file_atomically(ca_path, authority, strlen(authority), 0) != 0 ||
	    write_file_atomically(cert_path, certificate, strlen(certificate), 0) != 0 ||
	    write_file_atomically(key_path, key_pem, strlen(key_pem), 1) != 0) {
		rpclog("nexus_renew: Nexus issued a certificate that could not "
		       "be saved; this machine must be enrolled again\n");
		return NEXUS_RENEW_FAILED;
	}

	if (certificate_expiry(cert_path, &not_after) == 0) {
		char when[32];
		struct tm *utc = gmtime(&not_after);

		if (utc != NULL && strftime(when, sizeof(when), "%Y-%m-%d", utc) > 0) {
			rpclog("nexus_renew: renewed, now good until %s\n", when);
			return NEXUS_RENEW_DONE;
		}
	}

	rpclog("nexus_renew: renewed\n");
	return NEXUS_RENEW_DONE;
}
