#!/bin/bash
# Zag strict signing regression tests, run on macOS against this tree's
# sources: apps with extensions and frameworks signed per component, the
# raw-signer (no key export) path, cryptographic chain selection, and
# malformed or unsupported input. Everything is synthetic: throwaway local
# authorities (trusted by nothing, deleted afterwards), placeholder teams,
# arm64 iOS executables compiled here. Nothing contacts Apple.
#   OPENSSL_PREFIX  Homebrew openssl@3 (default: brew --prefix openssl@3)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../../src" && pwd)"
SOURCES="$(cd "$HERE/../../Sources" && pwd)"
SSL="${OPENSSL_PREFIX:-$(brew --prefix openssl@3 2>/dev/null || true)}"
[ -f "$SSL/lib/libcrypto.a" ] || { echo "SKIP: Homebrew openssl@3 (static libcrypto) is required" >&2; exit 3; }
OPENSSL="$SSL/bin/openssl"
WORK=$(mktemp -d "${TMPDIR:-/tmp/}zag-zsign-tests.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# The library, from this tree.
TARGET="$(uname -m)-apple-macos$(sw_vers -productVersion | cut -d. -f1)"
FLAGS=(-target "$TARGET" -std=c++17 -w -O1 -I"$SRC" -I"$SRC/common" -I"$SSL/include")
mkdir -p "$WORK/obj" "$WORK/include"
for f in archo.cpp bundle.cpp macho.cpp openssl.cpp signing.cpp zag_components.cpp \
	common/base64.cpp common/fs.cpp common/json.cpp common/log.cpp common/sha.cpp common/timer.cpp common/util.cpp; do
	clang++ "${FLAGS[@]}" -c "$SRC/$f" -o "$WORK/obj/${f//\//_}.o" &
done
for f in openssl_tools.mm zsign.mm; do
	clang++ "${FLAGS[@]}" -fobjc-arc -c "$SRC/$f" -o "$WORK/obj/$f.o" &
done
wait
libtool -static -o "$WORK/libzsign.a" "$WORK"/obj/*.o "$SSL/lib/libcrypto.a" 2>/dev/null
printf 'module Zsign {\n\theader "%s/include/Zsign.h"\n\texport *\n}\n' "$SRC" > "$WORK/include/module.modulemap"

# Authorities and identities (RSA 2048, like Apple Development certificates).
A="$WORK/pki"; mkdir -p "$A"
ca() { # name subject
	"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 30 -subj "$2" \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout "$A/$1.key" -out "$A/$1.pem" 2>/dev/null
	"$OPENSSL" x509 -in "$A/$1.pem" -outform DER -out "$A/$1.der"
}
leaf() { # name ca extensions [start end]
	"$OPENSSL" genrsa -traditional -out "$A/$1.key" 2048 2>/dev/null
	"$OPENSSL" req -new -key "$A/$1.key" -subj "/CN=Apple Development: Zag Test (TESTTEAM01)/OU=TESTTEAM01/O=Zag Test/C=US" -out "$A/$1.csr" 2>/dev/null
	printf '%s\n' "$3" > "$A/$1.ext"
	if [ $# -ge 5 ]; then
		"$OPENSSL" x509 -req -in "$A/$1.csr" -CA "$A/$2.pem" -CAkey "$A/$2.key" -set_serial "0x$(openssl rand -hex 8)" \
			-not_before "$4" -not_after "$5" -extfile "$A/$1.ext" -out "$A/$1.pem" 2>/dev/null
	else
		"$OPENSSL" x509 -req -in "$A/$1.csr" -CA "$A/$2.pem" -CAkey "$A/$2.key" -set_serial "0x$(openssl rand -hex 8)" \
			-days 30 -extfile "$A/$1.ext" -out "$A/$1.pem" 2>/dev/null
	fi
	"$OPENSSL" x509 -in "$A/$1.pem" -outform DER -out "$A/$1.der"
	"$OPENSSL" rsa -in "$A/$1.key" -outform DER -traditional -out "$A/$1.pkcs1.der" 2>/dev/null
}
CODE="keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
authorityKeyIdentifier=keyid"
ca test "/CN=Zag Test Intermediate (not Apple)/O=Zag Test/C=US"
ca fakewwdr "/CN=Apple Worldwide Developer Relations Certification Authority/OU=G3/O=Apple Inc./C=US"
leaf good test "$CODE"
leaf fake fakewwdr "$CODE"
leaf expired test "$CODE" 20200101000000Z 20200201000000Z
leaf noeku test "keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid"
leaf other test "$CODE"
"$OPENSSL" pkcs12 -export -inkey "$A/good.key" -in "$A/good.pem" -passout pass:zagtest -out "$A/good.p12"
"$OPENSSL" pkcs12 -export -legacy -inkey "$A/good.key" -in "$A/good.pem" -passout pass:zagtest -out "$A/good.legacy.p12"
# Invalid chains: an issuer that is not an authority, an expired
# intermediate, and a self-signed leaf.
leaf notca good "$CODE"
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -subj "/CN=Zag Old Intermediate/O=Zag Test/C=US" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
	-not_before 20200101000000Z -not_after 20200301000000Z -keyout "$A/oldca.key" -out "$A/oldca.pem" 2>/dev/null
"$OPENSSL" x509 -in "$A/oldca.pem" -outform DER -out "$A/oldca.der"
leaf underold oldca "$CODE" 20200102000000Z 20300101000000Z
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Apple Development: Zag Test (TESTTEAM01)/OU=TESTTEAM01/O=Zag Test/C=US" \
	-addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=critical,codeSigning" \
	-keyout "$A/selfsigned.key" -out "$A/selfsigned.pem" 2>/dev/null
"$OPENSSL" x509 -in "$A/selfsigned.pem" -outform DER -out "$A/selfsigned.der"

# arm64 iOS binaries: app and extension executables, a framework, a library.
B="$WORK/bin"; mkdir -p "$B"
printf 'int main(void) { return 0; }\n' | xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=16.4 -x c - -o "$B/exe"
printf 'int zag_kit(void) { return 1; }\n' | xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=16.4 -dynamiclib -install_name @rpath/Kit.framework/Kit -x c - -o "$B/Kit"
printf 'int zag_lib(void) { return 2; }\n' | xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=16.4 -dynamiclib -install_name @rpath/libzag.dylib -x c - -o "$B/libzag.dylib"

swiftc -parse-as-library -target "$TARGET" -I "$WORK/include" \
	"$SOURCES/zsign.swift" "$HERE/ZagStrictSigningTests.swift" \
	-Xlinker "$WORK/libzsign.a" -lc++ -framework Security -o "$WORK/tests" 2>&1 | grep -v warning || true
[ -x "$WORK/tests" ] || { echo "FAIL: tests did not build" >&2; exit 1; }
cd "$WORK"
ZAG_OPENSSL="$OPENSSL" ZAG_PKI="$A" ZAG_BIN="$B" ZAG_WORK="$WORK" "$WORK/tests" > "$WORK/log" 2>&1 || { grep -v '^>>>' "$WORK/log" | tail -30; exit 1; }
grep -aoE '(PASS|SUCCESS): .*' "$WORK/log"

# DER entitlements, byte for byte against codesign's own for the same plist:
# booleans, integers, nested dictionaries, arrays and unsorted keys.
D="$WORK/der"; mkdir -p "$D"
clang++ "${FLAGS[@]}" "$HERE/der-check.cpp" "$WORK/libzsign.a" -framework Foundation -framework Security -o "$D/der-check"
der_case() { # name plist-body
	printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTD/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>%s</dict></plist>\n' "$2" > "$D/$1.plist"
	cp "$B/exe" "$D/$1.bin"
	codesign -f -s - --entitlements "$D/$1.plist" "$D/$1.bin" 2>/dev/null
	python3 -I - "$D/$1.bin" "$D/$1.apple" <<'PY2'
import struct, sys
d = open(sys.argv[1], "rb").read(); off = 32
for _ in range(struct.unpack_from("<I", d, 16)[0]):
    cmd, size = struct.unpack_from("<II", d, off)
    if cmd == 0x1D: start, length = struct.unpack_from("<II", d, off + 8)
    off += size
blob = d[start:start + length]
for i in range(struct.unpack_from(">I", blob, 8)[0]):
    kind, o = struct.unpack_from(">II", blob, 12 + 8 * i)
    if kind == 7:
        open(sys.argv[2], "wb").write(blob[o + 8:o + struct.unpack_from(">I", blob, o + 4)[0]])
PY2
	"$D/der-check" "$D/$1.plist" "$D/$1.zsign" || { echo "FAIL: DER entitlements ($1) not built" >&2; exit 1; }
	cmp -s "$D/$1.apple" "$D/$1.zsign" || { echo "FAIL: DER entitlements ($1) differ from codesign's" >&2; exit 1; }
	echo "PASS: DER entitlements ($1) are byte-identical to codesign's"
}
der_case booleans '<key>get-task-allow</key><true/><key>com.apple.developer.healthkit</key><false/><key>application-identifier</key><string>TESTTEAM01.com.example.app</string>'
der_case integers '<key>a</key><integer>0</integer><key>b</key><integer>127</integer><key>c</key><integer>128</integer><key>d</key><integer>300</integer><key>e</key><integer>65535</integer><key>f</key><integer>-1</integer>'
der_case nested '<key>z-dict</key><dict><key>inner</key><string>x</string><key>flag</key><false/><key>deeper</key><dict><key>b</key><true/><key>a</key><array><string>1</string><string>2</string></array></dict></dict><key>a-list</key><array><string>TESTTEAM01.*</string><string>com.apple.token</string></array>'
echo "SUCCESS: 3 DER entitlement comparisons with codesign passed"
