#pragma once
#include "common.h"
#include "json.h"
#include "openssl.h"
#include <vector>
#include <map>

class ZBundle
{
public:
	ZBundle();

public:
	bool SignFolder(ZSignAsset* pSignAsset,
					const string& strFolder,
					const string& strBundleId,
					const string& strBundleVersion,
					const string& strDisplayName,
					const vector<string>& arrDylibFiles,
					bool bForce,
					bool bWeakInject,
					bool bEnableCache,
					bool excludeProvisioning);

private:
	bool SignNode(jvalue& jvNode);
	void GetNodeChangedFiles(jvalue& jvNode, bool dontGenerateEmbeddedMobileProvision);
	void GetChangedFiles(jvalue& jvNode, vector<string>& arrChangedFiles);
	bool ModifyPluginsBundleId(const string& strOldBundleId, const string& strNewBundleId);
	bool ModifyBundleInfo(const string& strBundleId, const string& strBundleVersion, const string& strDisplayName);

private:
	bool FindAppFolder(const string& strFolder, string& strAppFolder);
	bool GetObjectsToSign(const string& strFolder, jvalue& jvInfo);
	bool GetSignFolderInfo(const string& strFolder, jvalue& jvNode, bool bGetName = false);

private:
	bool GenerateCodeResources(const string& strFolder, jvalue& jvCodeRes);

private:
	bool			m_bForceSign;
	bool			m_bWeakInject;
	ZSignAsset*		m_pSignAsset;
	vector<string>	m_arrInjectDylibs;

public:
	string			m_strAppFolder;
	string signFailedFiles;
	// Zag strict signing: extensions by path relative to the app (for
	// example "PlugIns/Widget.appex"), each with its own profile and
	// entitlements; any other nested bundle except frameworks is refused.
	bool						m_bStrict;
	map<string, ZSignAsset*>	m_mapComponentAssets;
};
