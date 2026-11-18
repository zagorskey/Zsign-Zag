// Reports which chain the strict signer selects for a certificate (DER),
// e.g. one taken from an app signed by Apple's real WWDR intermediate.
#include "openssl.h"
#include "common.h"
#include <openssl/x509.h>

int main(int argc, char** argv)
{
	string der;
	if (argc < 2 || !ZFile::ReadFile(argv[1], der)) {
		return 2;
	}
	const unsigned char* p = (const unsigned char*)der.data();
	ZSignAsset asset;
	asset.m_x509Cert = d2i_X509(NULL, &p, (long)der.size());
	string error;
	if (!asset.SelectChain(error)) {
		printf("REFUSED: %s\n", error.c_str());
		return 1;
	}
	printf("%s\n", asset.m_bAppleChain ? "APPLE-WWDR" : "EXTRA");
	return 0;
}
