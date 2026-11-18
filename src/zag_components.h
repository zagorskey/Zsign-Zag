#pragma once
#include "common.h"
#include "openssl.h"
#include <map>
#include <vector>

// Zag strict signing: an app and each of its extensions signed for its own
// App ID, with its own profile and entitlements, by one identity; nothing is
// reported as signed until every signed binary has been read back and
// verified. Unsupported bundle types are refused before anything changes.

struct ZagComponentInput
{
	string strProvData;
	string strEntitleData;
};

struct ZagSignRequest
{
	// The .app folder, signed in place.
	string strAppFolder;
	// The certificate (DER), and either a key (PEM, DER or PKCS #12 data) or
	// a raw signer. With a key, the certificate may be left empty: the
	// profile's certificate for the key is used.
	string strCertDER;
	string strKeyData;
	string strKeyPassword;
	ZagRawSigner signer;
	// "" is the app itself; other keys are paths relative to the app, such
	// as "PlugIns/Widget.appex".
	map<string, ZagComponentInput> components;
	// Optional new bundle ID for the app; extension IDs keep their suffix.
	string strBundleId;
	// Intermediates (DER) accepted besides Apple's WWDR ones, for tests.
	vector<string> arrExtraIntermediates;
};

bool ZagSignApp(const ZagSignRequest& request, string& strError);

// Checks a signed app as iOS would see it: every Mach-O carries a CMS
// signature by `cert` over its code directory, the code directory's page
// hashes match the file, the team and identifiers are right, and each app
// and extension has exactly its entitlements and embedded profile.
bool ZagVerifySignedApp(const string& strAppFolder,
						void* cert,
						const string& strTeamId,
						const map<string, ZSignAsset*>& assets,
						string& strError);

// Verifies an already signed app against the certificate (DER) and each
// component's profile and entitlements, without changing it.
bool ZagVerifyApp(const string& strAppFolder, const string& strCertDER, const map<string, ZagComponentInput>& components, string& strError);
