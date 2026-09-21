#!/usr/bin/env bash
#
# Build wolfSSL and ngtcp2, which the Nexus Community Network needs.
#
# Nexus asks the emulator for two things it cannot do today: a P-256 key and a
# certificate signing request when a machine enrols, and QUIC with a client
# certificate on the wire. wolfSSL covers both, so there is one crypto library
# to carry rather than two.
#
# Usage:
#   ./build-quic-libs.sh --prefix DIR [--toolchain FILE] [--sudo] [--jobs N]
#
# ★ WHY FROM SOURCE, ON EVERY PLATFORM.
#
# Not for want of looking. Checked on 21/09/2026:
#
#   Homebrew        no ngtcp2 formula at all
#   Ubuntu 24.04    libngtcp2-dev is 0.12.1, backported from Debian 12; we
#                   need 1.25.0, which is a different era of the API
#   MSYS2           ngtcp2 is packaged, but built with the GnuTLS and OpenSSL
#                   backends only - no libngtcp2_crypto_wolfssl
#
# So ngtcp2 is a source build wherever it goes. Once that is true, building
# wolfSSL alongside it costs about eleven seconds and buys something worth
# having: all six platform/architecture combinations get the identical library
# with identical options, rather than whatever each distribution happened to
# enable. The class of bug that avoids is the one that only appears on the
# platform you cannot test.
#
# The alternative considered was ngtcp2 against stock OpenSSL, whose 3.5
# release added the QUIC TLS API ngtcp2 accepts (SSL_set_quic_tls_cbs).
# Windows and macOS have new enough OpenSSL from packages; Ubuntu 24.04 is
# frozen at 3.0.13, so Linux would have had to build OpenSSL from source -
# which is very much heavier than wolfSSL.
set -euo pipefail

# Bump together, and the CI cache key follows them.
WOLFSSL=5.9.2-stable
NGTCP2=1.25.0

PREFIX=""
TOOLCHAIN=""
SUDO=""
JOBS=$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 4)

while [ $# -gt 0 ]; do
	case "$1" in
	--prefix)    PREFIX="$2"; shift 2 ;;
	--toolchain) TOOLCHAIN="$2"; shift 2 ;;
	--jobs)      JOBS="$2"; shift 2 ;;
	--sudo)      SUDO=sudo; shift ;;
	-h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
	*)           echo "error: unknown option $1" >&2; exit 1 ;;
	esac
done

[ -n "$PREFIX" ] || { echo "error: --prefix is required" >&2; exit 1; }
command -v cmake >/dev/null || { echo "error: cmake not found" >&2; exit 1; }
command -v curl  >/dev/null || { echo "error: curl not found" >&2; exit 1; }

# Already there, at the versions asked for. CI caches the prefix, so this is
# the difference between twenty seconds and none.
STAMP="${PREFIX}/lib/.rpcemu-quic-libs"
WANT="wolfssl-${WOLFSSL} ngtcp2-${NGTCP2}"

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$WANT" ]; then
	echo "==> wolfSSL and ngtcp2 already built in ${PREFIX}"
	exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"

echo "==> fetch wolfSSL ${WOLFSSL} and ngtcp2 ${NGTCP2}"
curl -fsSL "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL}.tar.gz" -o wolfssl.tar.gz
curl -fsSL "https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2}/ngtcp2-${NGTCP2}.tar.gz" -o ngtcp2.tar.gz
tar xzf wolfssl.tar.gz
tar xzf ngtcp2.tar.gz

cmake_dep() { # <srcdir> <extra cmake args...>
	local src="$1"; shift
	local args=(-S "$src" -B "$src/b" -DCMAKE_INSTALL_PREFIX="$PREFIX"
	            -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$PREFIX"
	            -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF)

	[ -n "$TOOLCHAIN" ] && args+=(-DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN")

	cmake "${args[@]}" "$@"
	cmake --build "$src/b" -j"$JOBS"
	$SUDO cmake --install "$src/b"
}

# ★ Three of these are defines rather than options, and that is not a style
# choice: wolfSSL's CMake has no option for them. Without them ngtcp2's backend
# fails to link on wolfSSL_EVP_aes_128_ecb, wolfSSL_EVP_aes_256_ecb and
# wolfSSL_CTX_UseSessionTicket - AES in ECB mode is what QUIC header protection
# uses, and session tickets are what the backend configures. The autotools
# build gets them from --enable-all; this is that list, by hand.
echo "==> wolfSSL ${WOLFSSL}"
cmake_dep "wolfssl-${WOLFSSL}" \
	-DWOLFSSL_QUIC=ON -DWOLFSSL_TLS13=ON \
	-DWOLFSSL_OPENSSLALL=ON -DWOLFSSL_OPENSSLEXTRA=ON -DWOLFSSL_HARDEN=ON \
	-DWOLFSSL_CERTGEN=ON -DWOLFSSL_CERTREQ=ON -DWOLFSSL_KEYGEN=ON -DWOLFSSL_ECC=ON \
	-DWOLFSSL_EXAMPLES=OFF -DWOLFSSL_CRYPT_TESTS=OFF \
	-DCMAKE_C_FLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DHAVE_SESSION_TICKET -DWOLFSSL_EARLY_DATA -DHAVE_EX_DATA"

echo "==> ngtcp2 ${NGTCP2}"
cmake_dep "ngtcp2-${NGTCP2}" \
	-DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
	-DENABLE_WOLFSSL=ON -DENABLE_OPENSSL=OFF

$SUDO mkdir -p "$(dirname "$STAMP")"
echo "$WANT" | $SUDO tee "$STAMP" >/dev/null

echo
echo "wolfSSL ${WOLFSSL} and ngtcp2 ${NGTCP2} installed into ${PREFIX}."
