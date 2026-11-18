#pragma once
#include "json.h"
#include <functional>
#include <memory>
#include <vector>

// Signs a PKCS #1 DigestInfo with the signing key and returns the RSA
// PKCS #1 v1.5 signature (for a key that never leaves its key store, such
// as a Security framework key). Returns false on failure.
typedef std::function<bool(const string& strDigestInfo, string& strSignature)> ZagRawSigner;

class ZSignAsset
{
public:
	ZSignAsset();

public:
	bool Init(const string& strCertFile, 
				const string& strPKeyFile,
				const string& strProvFile,
				const string& strEntitleFile,
				const string& strPassword,
				bool bAdhoc,
				bool bSHA256Only,
				bool bSingleBinary);

	// Strict signing (Zag): the identity is a certificate plus either a key
	// (PEM, DER or PKCS #12 data, in memory) or a raw signer callback. The
	// certificate must match the key, be valid now, allow code signing and
	// be issued (cryptographically) by a known Apple WWDR intermediate or one
	// of the extra intermediates given (DER). Nothing is read from files.
	bool InitStrict(const string& strCertDER,
					const string& strKeyData,
					const string& strKeyPassword,
					ZagRawSigner signer,
					const string& strProvData,
					const string& strEntitleData,
					const vector<string>& arrExtraIntermediatesDER,
					string& strError);

	// Another bundle (an extension) signed by the same identity with its own
	// profile and entitlements.
	bool InitComponent(const ZSignAsset& identity,
					   const string& strProvData,
					   const string& strEntitleData,
					   string& strError);

	bool GenerateCMS(const string& strCDHashData, 
						const string& strCDHashesPlist, 
						const string& strCodeDirectorySlotSHA1, 
						const string& strAltnateCodeDirectorySlot256, 
						string& strCMSOutput);

private:
	bool GenerateCMS(void* pscert, 
						void* pspkey, 
						const string& strCDHashData, 
						const string& strCDHashesPlist, 
						const string& strCodeDirectorySlotSHA1, 
						const string& strAltnateCodeDirectorySlot256, 
						string& strCMSOutput);

	bool LoadPrivateKey(const string& strKeyData, const string& strPassword, void** ppKey, void** ppCert);

public:
	// Chooses the intermediate that issued m_x509Cert (see openssl.cpp).
	bool SelectChain(string& strError);

private:

	bool GetCertSubjectCN(void* cert, string& strSubjectCN);
	bool GetCertSubjectCN(const string& strCertData, string& strSubjectCN);

public:
	static bool		CMSError();
	static void*	GenerateASN1Type(const string& value);
	static bool		GetCertInfo(void* pcert, jvalue& jvCertInfo);
	static bool		GetCMSInfo(uint8_t* pCMSData, uint32_t uCMSLength, jvalue& jvOutput);
	static bool		GetCMSContent(const string& strCMSDataInput, string& strContentOutput);
	static void		ParseCertSubject(const string& strSubject, jvalue& jvSubject);
	static string	ASN1_TIMEtoString(const void* time);

public:
	bool	m_bAdhoc;
	bool	m_bSHA256Only;
	bool	m_bSingleBinary;
	string	m_strTeamId;
	string	m_strSubjectCN;
	string	m_strProvData;
	string	m_strEntitleData;

public:
	void*	m_evpPKey;
	void*	m_x509Cert;
	// The intermediate the certificate was verified against, and whether it
	// is Apple's (then Apple's root is added to the signature too).
	void*	m_x509Intermediate;
	string	m_strChainError;
	bool	m_bAppleChain;
	bool	m_bStrict;
	vector<string>	m_arrExtraIntermediates;
	std::shared_ptr<ZagRawSigner>	m_pSigner;

public:
	static const char* s_szAppleDevCACert;
	static const char* s_szAppleRootCACert;
	static const char* s_szAppleDevCACertG3;

public:
	class OpenSSLInit
	{
	public:
		OpenSSLInit();
	};
	static OpenSSLInit s_OpenSSLInit;
};
