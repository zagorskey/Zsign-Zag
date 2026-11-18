//
//  zsign.hpp
//  feather
//
//  Created by HAHALOSAH on 5/22/24.
//

#ifndef zsign_hpp
#define zsign_hpp

#include <stdio.h>
#import <Foundation/Foundation.h>




#ifdef __cplusplus
extern "C" {
#endif

NSString *ZagInspectAppleSecurityTrust(NSData *cmsDER);
NSString *ZagInspectCMSCertificateChain(NSData *cmsDER);
NSString *ZagVerifyDetachedCMS(NSData *cmsDER, NSData *codeDirectory);

bool CheckIfSigned(NSString *filePath);
bool InjectDyLib(NSString *filePath, NSString *dylibPath, bool weakInject);
bool UninstallDylibs(NSString *filePath, NSArray<NSString *> *dylibPathsArray);
NSArray<NSString *> *ListDylibs(NSString *filePath);
bool ChangeDylibPath(NSString *filePath, NSString *oldPath, NSString *newPath);

int zsign(
	NSString *app,
	NSString *prov,
	NSString *key,
	NSString *pass,
	NSString *entitlement,
	NSString *bundleid,
	NSString *displayname,
	NSString *bundleversion,
	bool adhoc,
	bool dontGenerateEmbeddedMobileProvision,
	bool sha256Only,
	void(^completionHandler)(BOOL success, NSError *error)
);

/// Zag strict signing: the app and each extension with its own profile and
/// entitlements (`components`: "" for the app, "PlugIns/X.appex" for each
/// extension, each {"provision": NSData, "entitlements": NSData}), by one
/// identity: the certificate (DER) with either key data (PEM, DER or
/// PKCS #12, in memory) or `signer`, which returns the RSA PKCS #1 v1.5
/// signature of a DigestInfo (or nil). Succeeds only when every signed
/// binary verifies; otherwise `error` says why and the app must be discarded.
typedef NSData *(^ZagRawSignerBlock)(NSData *digestInfo);

bool ZagSignComponents(
	NSString *app,
	NSData *certificate,
	NSData *keyData,
	NSString *keyPassword,
	ZagRawSignerBlock signer,
	NSDictionary<NSString *, NSDictionary<NSString *, NSData *> *> *components,
	NSString *bundleIdentifier,
	NSArray<NSData *> *extraIntermediates,
	NSString **error
);

/// Re-checks an app signed by `ZagSignComponents`, without changing it.
bool ZagVerifyComponents(
	NSString *app,
	NSData *certificate,
	NSDictionary<NSString *, NSDictionary<NSString *, NSData *> *> *components,
	NSString **error
);

int checkCert(
	NSString *prov,
	NSString *key,
	NSString *pass,
	void(^completionHandler)(int status, NSDate* expirationDate, NSString *error)
);

#ifdef __cplusplus
}
#endif

#endif /* zsign_hpp */
