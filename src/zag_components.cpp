#include "zag_components.h"
#include "bundle.h"
#include "sha.h"
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

// MARK: - Reading signed Mach-O files

namespace {

uint32_t ReadBE32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
uint32_t ReadLE32(const uint8_t* p) { return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0]; }

struct Slice
{
	const uint8_t* base;
	size_t size;
};

struct Signature
{
	map<uint32_t, string> blobs; // slot type -> blob bytes
	uint32_t codeLimitOffset = 0;  // where the signature starts in the slice
};

// The architectures in a Mach-O file (one for a thin file).
bool Slices(const string& file, vector<Slice>& slices)
{
	const uint8_t* p = (const uint8_t*)file.data();
	if (file.size() < 8) {
		return false;
	}
	uint32_t magicBE = ReadBE32(p);
	if (magicBE == 0xcafebabe || magicBE == 0xcafebabf) {
		bool wide = magicBE == 0xcafebabf;
		uint32_t count = ReadBE32(p + 4);
		size_t entry = wide ? 32 : 20;
		if (count == 0 || count > 32 || 8 + count * entry > file.size()) {
			return false;
		}
		for (uint32_t i = 0; i < count; i++) {
			const uint8_t* arch = p + 8 + i * entry;
			uint64_t offset = wide ? (((uint64_t)ReadBE32(arch + 8) << 32) | ReadBE32(arch + 12)) : ReadBE32(arch + 8);
			uint64_t size = wide ? (((uint64_t)ReadBE32(arch + 16) << 32) | ReadBE32(arch + 20)) : ReadBE32(arch + 12);
			if (offset + size > file.size()) {
				return false;
			}
			slices.push_back({ p + offset, (size_t)size });
		}
		return true;
	}
	uint32_t magicLE = ReadLE32(p);
	if (magicLE == 0xfeedfacf || magicLE == 0xfeedface) {
		slices.push_back({ p, file.size() });
		return true;
	}
	return false;
}

bool ReadSignature(const Slice& slice, Signature& signature, string& strError)
{
	uint32_t magic = ReadLE32(slice.base);
	size_t header = (magic == 0xfeedfacf) ? 32 : 28;
	if ((magic != 0xfeedfacf && magic != 0xfeedface) || slice.size < header) {
		strError = "not a Mach-O file";
		return false;
	}
	uint32_t ncmds = ReadLE32(slice.base + 16);
	size_t offset = header;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (offset + 8 > slice.size) {
			break;
		}
		uint32_t cmd = ReadLE32(slice.base + offset);
		uint32_t cmdsize = ReadLE32(slice.base + offset + 4);
		if (cmdsize < 8 || offset + cmdsize > slice.size) {
			break;
		}
		if (cmd == 0x1d) { // LC_CODE_SIGNATURE
			uint32_t dataoff = ReadLE32(slice.base + offset + 8);
			uint32_t datasize = ReadLE32(slice.base + offset + 12);
			if ((uint64_t)dataoff + datasize > slice.size || datasize < 12) {
				strError = "signature out of range";
				return false;
			}
			const uint8_t* sb = slice.base + dataoff;
			if (ReadBE32(sb) != 0xfade0cc0) {
				strError = "no embedded signature";
				return false;
			}
			uint32_t length = ReadBE32(sb + 4), count = ReadBE32(sb + 8);
			if (length > datasize || 12 + (uint64_t)count * 8 > length) {
				strError = "damaged signature";
				return false;
			}
			for (uint32_t j = 0; j < count; j++) {
				uint32_t type = ReadBE32(sb + 12 + j * 8), at = ReadBE32(sb + 16 + j * 8);
				if ((uint64_t)at + 8 > length) {
					strError = "damaged signature";
					return false;
				}
				uint32_t blobLength = ReadBE32(sb + at + 4);
				if (blobLength < 8 || (uint64_t)at + blobLength > length) {
					strError = "damaged signature";
					return false;
				}
				signature.blobs[type] = string((const char*)sb + at, blobLength);
			}
			signature.codeLimitOffset = dataoff;
			return true;
		}
		offset += cmdsize;
	}
	strError = "unsigned";
	return false;
}

struct CodeDirectory
{
	uint32_t hashOffset = 0, nSpecialSlots = 0, nCodeSlots = 0, codeLimit = 0;
	uint8_t hashSize = 0, hashType = 0, pageSizeLog2 = 0;
	string identifier, teamId;
};

bool ParseCodeDirectory(const string& blob, CodeDirectory& cd)
{
	const uint8_t* p = (const uint8_t*)blob.data();
	if (blob.size() < 44 || ReadBE32(p) != 0xfade0c02) {
		return false;
	}
	uint32_t version = ReadBE32(p + 8);
	cd.hashOffset = ReadBE32(p + 16);
	uint32_t identOffset = ReadBE32(p + 20);
	cd.nSpecialSlots = ReadBE32(p + 24);
	cd.nCodeSlots = ReadBE32(p + 28);
	cd.codeLimit = ReadBE32(p + 32);
	cd.hashSize = p[36];
	cd.hashType = p[37];
	cd.pageSizeLog2 = p[39];
	if (identOffset >= blob.size()) {
		return false;
	}
	cd.identifier = string((const char*)p + identOffset);
	if (version >= 0x20200 && blob.size() >= 52) {
		uint32_t teamOffset = ReadBE32(p + 48);
		if (teamOffset && teamOffset < blob.size()) {
			cd.teamId = string((const char*)p + teamOffset);
		}
	}
	uint64_t end = (uint64_t)cd.hashOffset + (uint64_t)cd.nCodeSlots * cd.hashSize;
	return cd.hashOffset >= (uint64_t)cd.nSpecialSlots * cd.hashSize && end <= blob.size()
		&& (cd.hashType == 1 || cd.hashType == 2) && cd.hashSize > 0 && cd.hashSize <= 32;
}

string Hash(uint8_t type, const void* data, size_t size, size_t length)
{
	unsigned char out[SHA256_DIGEST_LENGTH];
	if (type == 1) {
		SHA1((const unsigned char*)data, size, out);
	} else {
		SHA256((const unsigned char*)data, size, out);
	}
	return string((const char*)out, length);
}

bool SpecialSlotMatches(const string& cdBlob, const CodeDirectory& cd, uint32_t slot, const string& content)
{
	if (slot > cd.nSpecialSlots) {
		return false;
	}
	string expected = cdBlob.substr(cd.hashOffset - slot * cd.hashSize, cd.hashSize);
	return expected == Hash(cd.hashType, content.data(), content.size(), cd.hashSize);
}

// Checks one binary. `bundleExe`: the executable of an app or extension, so
// its Info.plist, CodeResources, identifier and entitlements are checked.
bool VerifyBinary(const string& path, X509* cert, const string& teamId, const ZSignAsset* asset,
				  const string& bundleFolder, const string& bundleId, string& strError)
{
	string file;
	vector<Slice> slices;
	if (!ZFile::ReadFile(path.c_str(), file) || !Slices(file, slices)) {
		strError = "not a Mach-O file";
		return false;
	}
	for (const Slice& slice : slices) {
		Signature signature;
		if (!ReadSignature(slice, signature, strError)) {
			return false;
		}
		CodeDirectory cd;
		if (!signature.blobs.count(0) || !ParseCodeDirectory(signature.blobs[0], cd)) {
			strError = "no code directory";
			return false;
		}
		// Alternate code directories (SHA-256) must cover the same code.
		for (uint32_t slot = 0x1000; slot < 0x1005; slot++) {
			if (!signature.blobs.count(slot)) {
				continue;
			}
			CodeDirectory alt;
			const string& altBlob = signature.blobs[slot];
			if (!ParseCodeDirectory(altBlob, alt) || alt.teamId != teamId || alt.codeLimit != cd.codeLimit || alt.identifier != cd.identifier) {
				strError = "an alternate code directory does not match";
				return false;
			}
			size_t altPage = (size_t)1 << alt.pageSizeLog2;
			for (uint32_t i = 0; i < alt.nCodeSlots; i++) {
				size_t start = (size_t)i * altPage;
				if (start >= alt.codeLimit) {
					strError = "an alternate code directory does not match";
					return false;
				}
				size_t length = std::min(altPage, (size_t)alt.codeLimit - start);
				if (altBlob.compare(alt.hashOffset + i * alt.hashSize, alt.hashSize, Hash(alt.hashType, slice.base + start, length, alt.hashSize)) != 0) {
					strError = "the code does not match its alternate code directory";
					return false;
				}
			}
		}
		if (!signature.blobs.count(0x10000) || signature.blobs[0x10000].size() <= 8) {
			strError = "no CMS signature";
			return false;
		}
		if (cd.teamId != teamId) {
			strError = "wrong team in the code directory";
			return false;
		}

		// Every page of code is what the code directory says.
		size_t pageSize = (size_t)1 << cd.pageSizeLog2;
		if (cd.codeLimit != signature.codeLimitOffset || cd.codeLimit > slice.size
			|| cd.nCodeSlots != (cd.codeLimit + pageSize - 1) / pageSize) {
			strError = "the code directory does not cover the code";
			return false;
		}
		const string& cdBlob = signature.blobs[0];
		for (uint32_t i = 0; i < cd.nCodeSlots; i++) {
			size_t start = (size_t)i * pageSize, length = std::min(pageSize, (size_t)cd.codeLimit - start);
			if (cdBlob.compare(cd.hashOffset + i * cd.hashSize, cd.hashSize, Hash(cd.hashType, slice.base + start, length, cd.hashSize)) != 0) {
				strError = "the code does not match its code directory";
				return false;
			}
		}

		// The CMS signature is the identity's, over this code directory.
		const string& cmsBlob = signature.blobs[0x10000];
		BIO* in = BIO_new_mem_buf(cmsBlob.data() + 8, (int)cmsBlob.size() - 8);
		CMS_ContentInfo* cms = in ? d2i_CMS_bio(in, NULL) : NULL;
		BIO_free(in);
		BIO* content = BIO_new_mem_buf(cdBlob.data(), (int)cdBlob.size());
		bool verified = cms && content && 1 == CMS_verify(cms, NULL, NULL, content, NULL, CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY);
		bool bySigner = false;
		if (verified) {
			STACK_OF(X509)* signers = CMS_get0_signers(cms);
			bySigner = signers && sk_X509_num(signers) == 1 && 0 == X509_cmp(sk_X509_value(signers, 0), cert);
			sk_X509_free(signers);
		}
		BIO_free(content);
		CMS_ContentInfo_free(cms);
		ERR_clear_error();
		if (!verified) {
			strError = "the CMS signature does not verify";
			return false;
		}
		if (!bySigner) {
			strError = "signed by another certificate";
			return false;
		}

		if (asset) {
			if (cd.identifier != bundleId) {
				strError = "wrong identifier in the code directory";
				return false;
			}
			string info, resources;
			if (!ZFile::ReadFile((bundleFolder + "/Info.plist").c_str(), info) || !SpecialSlotMatches(cdBlob, cd, 1, info)) {
				strError = "Info.plist is not sealed";
				return false;
			}
			if (!ZFile::ReadFile((bundleFolder + "/_CodeSignature/CodeResources").c_str(), resources) || !SpecialSlotMatches(cdBlob, cd, 3, resources)) {
				strError = "the bundle's resources are not sealed";
				return false;
			}
			const string entitlements = signature.blobs.count(5) ? signature.blobs[5] : string();
			if (entitlements.size() < 8 || ReadBE32((const uint8_t*)entitlements.data()) != 0xfade7171
				|| entitlements.substr(8) != asset->m_strEntitleData || !SpecialSlotMatches(cdBlob, cd, 5, entitlements)) {
				strError = "the entitlements are not this bundle's";
				return false;
			}
		}
	}
	return true;
}

string InfoValue(const string& folder, const char* key)
{
	jvalue info;
	if (!info.read_plist_from_file("%s/Info.plist", folder.c_str())) {
		return "";
	}
	return info[key].as_cstr();
}

string RelativePath(const string& root, const string& path)
{
	return path.size() > root.size() ? path.substr(root.size() + 1) : "";
}

// Bundles inside the app that strict signing does not support, or that
// have no profile. Frameworks are signed with the app's identity and no
// entitlements.
bool CheckStructure(const string& app, const map<string, ZagComponentInput>& components, string& strError)
{
	vector<string> problems;
	ZFile::EnumFolder(app.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
		if (!bFolder) {
			return false;
		}
		string rel = RelativePath(app, strPath);
		if (rel.rfind("Watch/", 0) == 0 || rel == "Watch") {
			problems.push_back(rel + ": Apple Watch apps are not supported");
		} else if (rel.rfind("AppClips/", 0) == 0 || rel == "AppClips") {
			problems.push_back(rel + ": App Clips are not supported");
		} else if (ZFile::IsPathSuffix(strPath, ".xpc")) {
			problems.push_back(rel + ": XPC services are not supported");
		} else if (ZFile::IsPathSuffix(strPath, ".xctest")) {
			problems.push_back(rel + ": test bundles are not supported");
		} else if (ZFile::IsPathSuffix(strPath, ".app")) {
			problems.push_back(rel + ": nested apps are not supported");
		} else if (ZFile::IsPathSuffix(strPath, ".appex")) {
			string parent = rel.substr(0, rel.rfind('/'));
			if (parent != "PlugIns" && parent != "Extensions") {
				problems.push_back(rel + ": extensions inside other bundles are not supported");
			} else if (!components.count(rel)) {
				problems.push_back(rel + ": no provisioning profile for this extension");
			}
		}
		return false;
	});
	for (auto& component : components) {
		if (!component.first.empty() && (!ZFile::IsPathSuffix(component.first, ".appex") || !ZFile::IsFolderV("%s/%s", app.c_str(), component.first.c_str()))) {
			problems.push_back(component.first + ": not an extension in this app");
		}
	}
	if (!problems.empty()) {
		strError = problems[0];
		for (size_t i = 1; i < problems.size(); i++) {
			strError += "\n" + problems[i];
		}
		return false;
	}
	return true;
}

bool PatternMatches(const string& pattern, const string& value)
{
	if (!pattern.empty() && pattern.back() == '*') {
		return value.compare(0, pattern.size() - 1, pattern, 0, pattern.size() - 1) == 0;
	}
	return pattern == value;
}

// Whether the profile allows an entitlement's value, by the rules iOS
// applies when it installs an app: a profile value of "*" allows anything;
// strings match exactly or by a trailing "*"; every element of an array
// must be allowed by the profile's array (or string); a boolean may be true
// only where the profile's is true. Other kinds of value (numbers,
// dictionaries, data) are refused rather than guessed.
bool ValueAllowed(const jvalue& allowed, const jvalue& value)
{
	if (allowed.is_string() && string(allowed.as_cstr()) == "*") {
		return true;
	}
	if (value.is_bool()) {
		return allowed.is_bool() && (!value.as_bool() || allowed.as_bool());
	}
	if (value.is_string()) {
		if (allowed.is_string()) {
			return PatternMatches(allowed.as_cstr(), value.as_cstr());
		}
		if (allowed.is_array()) {
			for (size_t i = 0; i < allowed.size(); i++) {
				if (allowed.at(i).is_string() && PatternMatches(allowed.at(i).as_cstr(), value.as_cstr())) {
					return true;
				}
			}
		}
		return false;
	}
	if (value.is_array() && (allowed.is_array() || allowed.is_string())) {
		for (size_t i = 0; i < value.size(); i++) {
			if (!value.at(i).is_string() || !ValueAllowed(allowed, value.at(i))) {
				return false;
			}
		}
		return true;
	}
	return false;
}

// The profile is for this team and App ID, still valid, and allows every
// entitlement, and every value, the bundle will be signed with.
bool CheckComponent(const string& name, const ZSignAsset& asset, const string& bundleId, const string& mainBundleId, string& strError)
{
	string content;
	jvalue profile, entitlements;
	if (!ZSignAsset::GetCMSContent(asset.m_strProvData, content) || !profile.read_plist(content)) {
		strError = name + ": the provisioning profile cannot be read";
		return false;
	}
	if (!entitlements.read_plist(asset.m_strEntitleData) || !entitlements.is_object()) {
		strError = name + ": the entitlements cannot be read";
		return false;
	}
	if (!profile.is_object() || !profile["Entitlements"].is_object() || !profile["ExpirationDate"].is_date()
		|| !profile["Entitlements"]["application-identifier"].is_string()) {
		strError = name + ": the provisioning profile is incomplete (entitlements, App ID or expiry missing)";
		return false;
	}
	if (profile["ExpirationDate"].as_date() <= time(NULL)) {
		strError = name + ": the provisioning profile has expired";
		return false;
	}
	if (profile["Entitlements"].has("com.apple.developer.team-identifier")
		&& string(profile["Entitlements"]["com.apple.developer.team-identifier"].as_cstr()) != asset.m_strTeamId) {
		strError = name + ": the provisioning profile's entitlements are for another team";
		return false;
	}
	if (bundleId.empty() || (!mainBundleId.empty() && bundleId.rfind(mainBundleId + ".", 0) != 0)) {
		strError = name + ": the extension's bundle ID must start with the app's";
		return false;
	}
	string appID = asset.m_strTeamId + "." + bundleId;
	if (!PatternMatches(profile["Entitlements"]["application-identifier"].as_cstr(), appID)) {
		strError = name + ": the provisioning profile is for another App ID";
		return false;
	}
	if (string(entitlements["application-identifier"].as_cstr()) != appID) {
		strError = name + ": the entitlements are for another App ID";
		return false;
	}
	if (entitlements.has("com.apple.developer.team-identifier") && string(entitlements["com.apple.developer.team-identifier"].as_cstr()) != asset.m_strTeamId) {
		strError = name + ": the entitlements are for another team";
		return false;
	}
	vector<string> keys;
	entitlements.get_keys(keys);
	for (const string& key : keys) {
		if (!profile["Entitlements"].has(key)) {
			strError = name + ": the provisioning profile does not allow " + key;
			return false;
		}
		if (!ValueAllowed(profile["Entitlements"][key], entitlements[key])) {
			strError = name + ": the provisioning profile does not allow this value of " + key;
			return false;
		}
	}
	// Groups the entitlements name must belong to this team or be app groups.
	// The one exception is com.apple.token, Apple's shared CryptoTokenKit
	// group, which Apple's own profiles list next to TEAM.*; like every value,
	// it is allowed only when the profile lists it (checked above).
	const jvalue& keychain = entitlements["keychain-access-groups"];
	for (size_t i = 0; keychain.is_array() && i < keychain.size(); i++) {
		const string group = keychain.at(i).as_cstr();
		if (group != "com.apple.token" && group.rfind(asset.m_strTeamId + ".", 0) != 0) {
			strError = name + ": a keychain access group belongs to another team";
			return false;
		}
	}
	const jvalue& groups = entitlements["com.apple.security.application-groups"];
	for (size_t i = 0; groups.is_array() && i < groups.size(); i++) {
		if (string(groups.at(i).as_cstr()).rfind("group.", 0) != 0) {
			strError = name + ": an app group must start with \"group.\"";
			return false;
		}
	}
	return true;
}

} // namespace

// MARK: - Signing

bool ZagVerifySignedApp(const string& strAppFolder, void* cert, const string& strTeamId, const map<string, ZSignAsset*>& assets, string& strError)
{
	// The app and each extension: executable, identifier, entitlements, profile.
	for (auto& entry : assets) {
		string folder = entry.first.empty() ? strAppFolder : strAppFolder + "/" + entry.first;
		string name = entry.first.empty() ? "the app" : entry.first;
		string exe = InfoValue(folder, "CFBundleExecutable"), bundleId = InfoValue(folder, "CFBundleIdentifier");
		string embedded;
		if (!ZFile::ReadFile((folder + "/embedded.mobileprovision").c_str(), embedded) || embedded != entry.second->m_strProvData) {
			strError = name + ": the embedded profile is not the one it was signed for";
			return false;
		}
		if (exe.empty() || !VerifyBinary(folder + "/" + exe, (X509*)cert, strTeamId, entry.second, folder, bundleId, strError)) {
			strError = name + ": " + strError;
			return false;
		}
	}
	// Every other Mach-O: frameworks and libraries.
	bool ok = true;
	ZFile::EnumFolder(strAppFolder.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
		if (!ok) {
			return true;
		}
		string binary;
		if (bFolder && ZFile::IsPathSuffix(strPath, ".framework")) {
			string exe = InfoValue(strPath, "CFBundleExecutable");
			string base = ZUtil::GetBaseName(strPath.c_str());
			binary = strPath + "/" + (exe.empty() ? base.substr(0, base.size() - strlen(".framework")) : exe);
		} else if (!bFolder && ZFile::IsPathSuffix(strPath, ".dylib")) {
			binary = strPath;
		}
		if (!binary.empty() && !VerifyBinary(binary, (X509*)cert, strTeamId, NULL, "", "", strError)) {
			strError = RelativePath(strAppFolder, binary) + ": " + strError;
			ok = false;
			return true;
		}
		return false;
	});
	return ok;
}

bool ZagSignApp(const ZagSignRequest& request, string& strError)
{
	string app = request.strAppFolder;
	while (app.size() > 1 && app.back() == '/') {
		app.pop_back();
	}
	if (!ZFile::IsPathSuffix(app, ".app") || !ZFile::IsFolder(app.c_str())) {
		strError = "Not an app bundle.";
		return false;
	}
	map<string, ZagComponentInput>::const_iterator main = request.components.find("");
	if (main == request.components.end()) {
		strError = "No provisioning profile for the app.";
		return false;
	}
	if (!CheckStructure(app, request.components, strError)) {
		return false;
	}

	ZSignAsset identity;
	if (!identity.InitStrict(request.strCertDER, request.strKeyData, request.strKeyPassword, request.signer,
							 main->second.strProvData, main->second.strEntitleData, request.arrExtraIntermediates, strError)) {
		return false;
	}
	vector<std::unique_ptr<ZSignAsset>> owned;
	map<string, ZSignAsset*> assets;
	assets[""] = &identity;
	for (auto& component : request.components) {
		if (component.first.empty()) {
			continue;
		}
		owned.emplace_back(new ZSignAsset());
		if (!owned.back()->InitComponent(identity, component.second.strProvData, component.second.strEntitleData, strError)) {
			strError = component.first + ": " + strError;
			return false;
		}
		assets[component.first] = owned.back().get();
	}

	// Bundle IDs as they will be signed, checked against each profile
	// before anything is changed on disk.
	string mainBefore = InfoValue(app, "CFBundleIdentifier");
	string mainAfter = request.strBundleId.empty() ? mainBefore : request.strBundleId;
	for (auto& entry : assets) {
		string id = entry.first.empty() ? mainAfter : InfoValue(app + "/" + entry.first, "CFBundleIdentifier");
		if (!entry.first.empty() && !request.strBundleId.empty()) {
			ZUtil::StringReplace(id, mainBefore, mainAfter);
		}
		if (!CheckComponent(entry.first.empty() ? "the app" : entry.first, *entry.second, id, entry.first.empty() ? "" : mainAfter, strError)) {
			return false;
		}
	}

	ZBundle bundle;
	bundle.m_bStrict = true;
	for (auto& entry : assets) {
		if (!entry.first.empty()) {
			bundle.m_mapComponentAssets[entry.first] = entry.second;
		}
	}
	vector<string> noDylibs;
	bool signed_ = bundle.SignFolder(&identity, app, request.strBundleId, "", "", noDylibs, true, false, false, true);
	if (!signed_ || !bundle.signFailedFiles.empty()) {
		strError = "Signing failed." + (bundle.signFailedFiles.empty() ? string() : "\n" + bundle.signFailedFiles);
		return false;
	}
	if (!ZagVerifySignedApp(app, identity.m_x509Cert, identity.m_strTeamId, assets, strError)) {
		strError = "The signed app did not verify: " + strError;
		return false;
	}
	return true;
}

bool ZagVerifyApp(const string& strAppFolder, const string& strCertDER, const map<string, ZagComponentInput>& components, string& strError)
{
	const unsigned char* p = (const unsigned char*)strCertDER.data();
	X509* cert = d2i_X509(NULL, &p, (long)strCertDER.size());
	if (NULL == cert) {
		strError = "The certificate cannot be read.";
		return false;
	}
	vector<std::unique_ptr<ZSignAsset>> owned;
	map<string, ZSignAsset*> assets;
	string strTeamId;
	for (auto& component : components) {
		owned.emplace_back(new ZSignAsset());
		ZSignAsset* asset = owned.back().get();
		asset->m_strProvData = component.second.strProvData;
		asset->m_strEntitleData = component.second.strEntitleData;
		string content;
		jvalue profile;
		if (!ZSignAsset::GetCMSContent(asset->m_strProvData, content) || !profile.read_plist(content)) {
			X509_free(cert);
			strError = "A provisioning profile cannot be read.";
			return false;
		}
		asset->m_strTeamId = profile["TeamIdentifier"][0].as_cstr();
		if (strTeamId.empty()) {
			strTeamId = asset->m_strTeamId;
		}
		assets[component.first] = asset;
	}
	bool ok = !strTeamId.empty() && assets.count("") && ZagVerifySignedApp(strAppFolder, cert, strTeamId, assets, strError);
	if (!ok && strError.empty()) {
		strError = "No profile for the app.";
	}
	X509_free(cert);
	return ok;
}
