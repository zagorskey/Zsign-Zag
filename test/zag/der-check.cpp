// Writes Zsign's DER entitlements for a plist (without the 8-byte blob
// header), so run-tests.sh can compare them byte for byte with codesign's.
#include "common.h"
#include "json.h"
#include "mach-o.h"
#include "openssl.h"
#include "signing.h"
#include <fstream>
#include <iostream>
#include <sstream>

int main(int argc, char* argv[])
{
	if (argc != 3) return 2;
	std::ifstream in(argv[1], std::ios::binary);
	std::stringstream plist;
	plist << in.rdbuf();
	string der;
	if (!ZSign::SlotBuildDerEntitlements(plist.str(), der) || der.size() < 8) return 1;
	std::ofstream(argv[2], std::ios::binary).write(der.data() + 8, der.size() - 8);
	return 0;
}
