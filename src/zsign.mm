//
//  zsign.mm
//  feather
//
//  Created by HAHALOSAH on 5/22/24.
//

#include "zsign.hpp"
#include "common.h"
#include "openssl.h"
#include "macho.h"
#include "bundle.h"
#include "openssl.h"
#include "timer.h"
#include "archive.h"

#import <Security/Security.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <limits.h>

extern "C" {

// Read-only X.509 path validation against the bundled Apple root.
// This does not check revocation, provisioning, entitlements, or iOS policy.
NSString *ZagInspectCMSCertificateChain(NSData *cmsDER) {
    if (!cmsDER || cmsDER.length == 0 || cmsDER.length > INT_MAX)
        return @"UNVERIFIED — invalid CMS input";

    const unsigned char *cursor = (const unsigned char *)cmsDER.bytes;
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)cmsDER.length);
    if (!cms || cursor != (const unsigned char *)cmsDER.bytes + cmsDER.length) {
        CMS_ContentInfo_free(cms);
        return @"FAIL — malformed CMS DER";
    }

    NSString *result = @"UNVERIFIED — certificate path not checked";
    // CMS_get0_signers may return NULL when signer certificates are not
    // embedded. Inspect embedded certificates and signer identifiers first.
    STACK_OF(CMS_SignerInfo) *signerInfos = CMS_get0_SignerInfos(cms);
    STACK_OF(X509) *untrusted = CMS_get1_certs(cms);
    X509 *matchedSigner = NULL;
    int matchingCertificates = 0;
    // Resolve by the CMS SignerIdentifier (issuer/serial or subject key ID),
    // not by certificate order or a guessed common name.
    if (signerInfos && sk_CMS_SignerInfo_num(signerInfos) == 1 && untrusted) {
        CMS_SignerInfo *info = sk_CMS_SignerInfo_value(signerInfos, 0);
        for (int i = 0; i < sk_X509_num(untrusted); ++i) {
            X509 *candidate = sk_X509_value(untrusted, i);
            if (CMS_SignerInfo_cert_cmp(info, candidate) == 0) {
                matchedSigner = candidate;
                ++matchingCertificates;
            }
        }
    }
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    BIO *rootBIO = BIO_new_mem_buf(
        ZSignAsset::s_szAppleRootCACert, -1);
    X509 *root = rootBIO ? PEM_read_bio_X509(rootBIO, NULL, NULL, NULL) : NULL;

    do {
        if (!matchedSigner || matchingCertificates != 1) {
            result = [NSString stringWithFormat:
                @"UNVERIFIED — signer identifier matches %d of %d embedded certificates (signerInfos=%d).",
                matchingCertificates, untrusted ? sk_X509_num(untrusted) : 0,
                signerInfos ? sk_CMS_SignerInfo_num(signerInfos) : 0];
            break;
        }
        if (!store) {
            result = @"UNVERIFIED — X.509 trust store allocation failed";
            break;
        }
        if (!context) {
            result = @"UNVERIFIED — X.509 verification context allocation failed";
            break;
        }
        if (!root) {
            const unsigned long code = ERR_peek_last_error();
            result = [NSString stringWithFormat:
                @"UNVERIFIED — bundled Apple root certificate could not be parsed (OpenSSL %lu)",
                code];
            break;
        }
        if (X509_STORE_add_cert(store, root) != 1) {
            result = @"UNVERIFIED — Apple root could not be loaded";
            break;
        }
        if (X509_STORE_CTX_init(
                context, store, matchedSigner, untrusted) != 1) {
            result = @"UNVERIFIED — certificate-chain initialization failed";
            break;
        }
        // Code-signing policy is separate; do not apply the S/MIME purpose.
        X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(context);
        X509_VERIFY_PARAM_set_purpose(parameters, X509_PURPOSE_ANY);
        const int verified = X509_verify_cert(context);
        if (verified == 1) {
            result = @"PASS — X.509 path to bundled Apple root verified at device time. Revocation, code-signing policy, provisioning and installation remain UNVERIFIED.";
        } else {
            const int error = X509_STORE_CTX_get_error(context);
            const char *description = X509_verify_cert_error_string(error);
            if (error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) {
                X509 *problem = X509_STORE_CTX_get_current_cert(context);
                const int depth = X509_STORE_CTX_get_error_depth(context);
                NSMutableArray<NSString *> *criticalOIDs = [NSMutableArray array];
                if (problem) {
                    const int extensionCount = X509_get_ext_count(problem);
                    for (int i = 0; i < extensionCount; ++i) {
                        X509_EXTENSION *extension = X509_get_ext(problem, i);
                        if (!extension || X509_EXTENSION_get_critical(extension) != 1)
                            continue;
                        ASN1_OBJECT *oid = X509_EXTENSION_get_object(extension);
                        char buffer[128] = {0};
                        if (oid && OBJ_obj2txt(buffer, sizeof(buffer), oid, 1) > 0)
                            [criticalOIDs addObject:[NSString stringWithUTF8String:buffer]];
                    }
                }
                result = [NSString stringWithFormat:
                    @"FAIL — unhandled critical extension (depth %d; critical OIDs: %@). Certificate trust NOT established.",
                    depth, criticalOIDs.count ? [criticalOIDs componentsJoinedByString:@", "] : @"none found"];
            } else {
                result = [NSString stringWithFormat:
                    @"FAIL — X.509 chain: %s (code %d). Installation NOT authorized.",
                    description ? description : "unknown", error];
            }
        }
    } while (false);

    X509_free(root);
    BIO_free(rootBIO);
    X509_STORE_CTX_free(context);
    X509_STORE_free(store);
    if (untrusted) sk_X509_pop_free(untrusted, X509_free);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return result;
}

// Read-only Apple Security framework trust evaluation. This is a basic X.509
// policy, not an iOS code-signing or provisioning authorization decision.
NSString *ZagInspectAppleSecurityTrust(NSData *cmsDER) {
    if (!cmsDER || cmsDER.length == 0 || cmsDER.length > INT_MAX)
        return @"UNVERIFIED — invalid CMS input";
    const unsigned char *cursor = (const unsigned char *)cmsDER.bytes;
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)cmsDER.length);
    if (!cms || cursor != (const unsigned char *)cmsDER.bytes + cmsDER.length) {
        CMS_ContentInfo_free(cms);
        return @"FAIL — malformed CMS DER";
    }
    NSString *result = @"UNVERIFIED — Security framework evaluation incomplete";
    STACK_OF(CMS_SignerInfo) *infos = CMS_get0_SignerInfos(cms);
    STACK_OF(X509) *embedded = CMS_get1_certs(cms);
    NSMutableArray *certificates = [NSMutableArray array];
    X509 *leaf = NULL;
    int matches = 0;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    do {
        if (!infos || sk_CMS_SignerInfo_num(infos) != 1 || !embedded) {
            result = @"UNVERIFIED — signer or embedded certificates missing";
            break;
        }
        CMS_SignerInfo *info = sk_CMS_SignerInfo_value(infos, 0);
        for (int i = 0; i < sk_X509_num(embedded); ++i) {
            X509 *candidate = sk_X509_value(embedded, i);
            if (CMS_SignerInfo_cert_cmp(info, candidate) == 0) {
                leaf = candidate;
                ++matches;
            }
        }
        if (matches != 1) {
            result = [NSString stringWithFormat:
                @"UNVERIFIED — signer identifier matches %d certificates", matches];
            break;
        }
        // The signer certificate MUST be first in the SecTrust input array.
        for (int pass = 0; pass < 2; ++pass) {
            for (int i = 0; i < sk_X509_num(embedded); ++i) {
                X509 *candidate = sk_X509_value(embedded, i);
                if ((pass == 0) != (candidate == leaf)) continue;
                const int length = i2d_X509(candidate, NULL);
                if (length <= 0 || length > INT_MAX / 2) continue;
                NSMutableData *der = [NSMutableData dataWithLength:(NSUInteger)length];
                unsigned char *writeCursor = (unsigned char *)der.mutableBytes;
                if (i2d_X509(candidate, &writeCursor) != length) continue;
                SecCertificateRef certificate = SecCertificateCreateWithData(
                    kCFAllocatorDefault, (__bridge CFDataRef)der);
                if (certificate) {
                    [certificates addObject:(__bridge id)certificate];
                    CFRelease(certificate);
                }
            }
        }
        if (certificates.count < 1) {
            result = @"UNVERIFIED — Security certificate conversion failed";
            break;
        }
        policy = SecPolicyCreateBasicX509();
        if (!policy) {
            result = @"UNVERIFIED — Security X.509 policy unavailable";
            break;
        }
        OSStatus status = SecTrustCreateWithCertificates(
            (__bridge CFArrayRef)certificates, policy, &trust);
        if (status != errSecSuccess || !trust) {
            result = [NSString stringWithFormat:
                @"UNVERIFIED — SecTrust initialization status %d", (int)status];
            break;
        }
        CFErrorRef trustError = NULL;
        const Boolean valid = SecTrustEvaluateWithError(trust, &trustError);
        if (valid) {
            result = @"PASS — Apple Security basic X.509 trust evaluation. iOS code-signing policy, provisioning and installation remain UNVERIFIED.";
        } else {
            NSString *reason = trustError
                ? [(__bridge NSError *)trustError localizedDescription]
                : @"no detailed reason";
            result = [NSString stringWithFormat:
                @"FAIL — Apple Security basic X.509 trust: %@. Installation NOT authorized.", reason];
        }
        if (trustError) CFRelease(trustError);
    } while (false);
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    if (embedded) sk_X509_pop_free(embedded, X509_free);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return result;
}

// Experimental diagnostic only; never authorizes installation.
NSString *ZagVerifyDetachedCMS(NSData *cmsDER, NSData *codeDirectory) {
    if (!cmsDER || !codeDirectory ||
        cmsDER.length == 0 || codeDirectory.length < 40 ||
        cmsDER.length > INT_MAX || codeDirectory.length > INT_MAX) {
        return @"UNVERIFIED — invalid CMS or CodeDirectory input";
    }

    const unsigned char *cursor =
        (const unsigned char *)cmsDER.bytes;

    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(
        NULL, &cursor, (long)cmsDER.length
    );

    if (!cms || cursor !=
        (const unsigned char *)cmsDER.bytes + cmsDER.length) {
        CMS_ContentInfo_free(cms);
        return @"FAIL — malformed CMS DER";
    }

    NSString *result = @"FAIL — CMS verification incomplete";

    do {
        if (CMS_is_detached(cms) != 1) {
            result = @"FAIL — CMS is not detached";
            break;
        }

        STACK_OF(CMS_SignerInfo) *signers =
            CMS_get0_SignerInfos(cms);

        if (!signers || sk_CMS_SignerInfo_num(signers) != 1) {
            result = @"FAIL — expected exactly one signer";
            break;
        }

        CMS_SignerInfo *signer =
            sk_CMS_SignerInfo_value(signers, 0);

        X509_ALGOR *digestAlgorithm = NULL;
        CMS_SignerInfo_get0_algs(
            signer, NULL, NULL, &digestAlgorithm, NULL
        );

        if (!digestAlgorithm ||
            OBJ_obj2nid(digestAlgorithm->algorithm) != NID_sha256) {
            result = @"FAIL — expected SHA-256 CMS digest";
            break;
        }

        BIO *content = BIO_new_mem_buf(
            codeDirectory.bytes, (int)codeDirectory.length
        );

        if (!content) {
            result = @"FAIL — CMS input allocation";
            break;
        }

        ERR_clear_error();
        const int valid = CMS_verify(
            cms, NULL, NULL, content, NULL,
            CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
        );
        BIO_free(content);

        if (valid != 1) {
            result = @"FAIL — CMS signature or message digest";
            break;
        }

        // The CodeDirectory blob must be SHA-256 primary.
        const unsigned char *cd =
            (const unsigned char *)codeDirectory.bytes;

        const unsigned int magic =
            ((unsigned int)cd[0] << 24) |
            ((unsigned int)cd[1] << 16) |
            ((unsigned int)cd[2] << 8) | cd[3];

        if (magic != 0xfade0c02 ||
            cd[37] != 2 || cd[36] != 32) {
            result = @"FAIL — not a SHA-256 CodeDirectory";
            break;
        }

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(cd, codeDirectory.length, digest);

        // Apple hash-agility plist: OID 1.2.840.113635.100.9.1
        ASN1_OBJECT *plistOID =
            OBJ_txt2obj("1.2.840.113635.100.9.1", 1);

        if (!plistOID) {
            result = @"FAIL — cannot construct hash-agility OID";
            break;
        }

        const int attrIndex =
            CMS_signed_get_attr_by_OBJ(signer, plistOID, -1);

        const int duplicateIndex = attrIndex >= 0
            ? CMS_signed_get_attr_by_OBJ(signer, plistOID, attrIndex)
            : -1;

        ASN1_OBJECT_free(plistOID);

        if (attrIndex < 0 || duplicateIndex >= 0) {
            result = @"FAIL — missing or duplicate cdhashes attribute";
            break;
        }

        X509_ATTRIBUTE *attribute =
            CMS_signed_get_attr(signer, attrIndex);

        if (!attribute || X509_ATTRIBUTE_count(attribute) != 1) {
            result = @"FAIL — malformed cdhashes attribute";
            break;
        }

        ASN1_TYPE *value =
            X509_ATTRIBUTE_get0_type(attribute, 0);

        if (!value || value->type != V_ASN1_OCTET_STRING ||
            !value->value.octet_string) {
            result = @"FAIL — cdhashes is not an OCTET STRING";
            break;
        }

        ASN1_OCTET_STRING *octets = value->value.octet_string;

        NSData *plistData = [NSData dataWithBytes:octets->data
                                          length:(NSUInteger)octets->length];

        NSError *plistError = nil;
        id parsed = [NSPropertyListSerialization
            propertyListWithData:plistData
                         options:NSPropertyListImmutable
                          format:NULL
                           error:&plistError];

        if (plistError || ![parsed isKindOfClass:[NSDictionary class]]) {
            result = @"FAIL — malformed cdhashes plist";
            break;
        }

        id hashes = ((NSDictionary *)parsed)[@"cdhashes"];

        if (![hashes isKindOfClass:[NSArray class]] ||
            [(NSArray *)hashes count] != 1) {
            result = @"FAIL — expected one SHA-256 cdhash";
            break;
        }

        id actual = [(NSArray *)hashes objectAtIndex:0];

        if (![actual isKindOfClass:[NSData class]] ||
            [(NSData *)actual length] != 20 ||
            memcmp([(NSData *)actual bytes], digest, 20) != 0) {
            result = @"FAIL — cdhashes does not match CodeDirectory";
            break;
        }


        // V2 hash-agility validation. Zsign's encoder emits:
        // SEQUENCE { OBJECT IDENTIFIER sha256, OCTET STRING digest }.
        ASN1_OBJECT *v2OID = OBJ_txt2obj("1.2.840.113635.100.9.2", 1);
        if (!v2OID) {
            result = @"FAIL — cannot construct V2 OID";
            break;
        }
        const int v2Index = CMS_signed_get_attr_by_OBJ(signer, v2OID, -1);
        const int v2Duplicate = v2Index >= 0
            ? CMS_signed_get_attr_by_OBJ(signer, v2OID, v2Index) : -1;
        ASN1_OBJECT_free(v2OID);

        if (v2Index < 0 || v2Duplicate >= 0) {
            result = @"FAIL — missing or duplicate V2 attribute";
            break;
        }

        X509_ATTRIBUTE *v2Attribute = CMS_signed_get_attr(signer, v2Index);
        if (!v2Attribute || X509_ATTRIBUTE_count(v2Attribute) != 1) {
            result = @"FAIL — malformed V2 attribute";
            break;
        }

        ASN1_TYPE *v2Value = X509_ATTRIBUTE_get0_type(v2Attribute, 0);
        if (!v2Value || v2Value->type != V_ASN1_SEQUENCE ||
            !v2Value->value.sequence) {
            result = @"FAIL — V2 is not an ASN.1 sequence";
            break;
        }

        // ASN1_TYPE's sequence payload holds the complete DER encoding.
        const unsigned char *v2Cursor =
            ASN1_STRING_get0_data(v2Value->value.sequence);
        const long v2Length = ASN1_STRING_length(v2Value->value.sequence);
        if (!v2Cursor || v2Length <= 0) {
            result = @"FAIL — empty V2 sequence";
            break;
        }

        const unsigned char *v2End = v2Cursor + v2Length;
        STACK_OF(ASN1_TYPE) *fields =
            d2i_ASN1_SEQUENCE_ANY(NULL, &v2Cursor, v2Length);
        if (!fields || v2Cursor != v2End ||
            sk_ASN1_TYPE_num(fields) != 2) {
            if (fields) sk_ASN1_TYPE_pop_free(fields, ASN1_TYPE_free);
            result = @"FAIL — malformed V2 sequence";
            break;
        }

        ASN1_TYPE *algorithm = sk_ASN1_TYPE_value(fields, 0);
        ASN1_TYPE *hash = sk_ASN1_TYPE_value(fields, 1);
        const bool validV2 =
            algorithm && algorithm->type == V_ASN1_OBJECT &&
            algorithm->value.object &&
            OBJ_obj2nid(algorithm->value.object) == NID_sha256 &&
            hash && hash->type == V_ASN1_OCTET_STRING &&
            hash->value.octet_string &&
            hash->value.octet_string->length == SHA256_DIGEST_LENGTH &&
            memcmp(hash->value.octet_string->data, digest, SHA256_DIGEST_LENGTH) == 0;
        sk_ASN1_TYPE_pop_free(fields, ASN1_TYPE_free);

        if (!validV2) {
            result = @"FAIL — V2 SHA-256 digest mismatch or unsupported encoding";
            break;
        }

        // A fresh CMS decode avoids reusing mutated verification state.
        const unsigned char *negativeCursor =
            (const unsigned char *)cmsDER.bytes;

        CMS_ContentInfo *negativeCMS = d2i_CMS_ContentInfo(
            NULL, &negativeCursor, (long)cmsDER.length
        );

        if (!negativeCMS) {
            result = @"FAIL — negative-test CMS decoding";
            break;
        }

        NSMutableData *corrupted = [codeDirectory mutableCopy];
        unsigned char *bytes =
            (unsigned char *)corrupted.mutableBytes;
        bytes[corrupted.length / 2] ^= 0x01;

        BIO *tamperedContent = BIO_new_mem_buf(
            corrupted.bytes, (int)corrupted.length
        );

        if (!tamperedContent) {
            CMS_ContentInfo_free(negativeCMS);
            result = @"FAIL — negative-test input allocation";
            break;
        }

        ERR_clear_error();

        const int tamperedValid = CMS_verify(
            negativeCMS, NULL, NULL, tamperedContent, NULL,
            CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
        );

        const unsigned long failureCode = ERR_peek_last_error();
        const int failureReason = failureCode
            ? ERR_GET_REASON(failureCode) : 0;

        BIO_free(tamperedContent);
        CMS_ContentInfo_free(negativeCMS);

        if (tamperedValid == 1) {
            result = @"FAIL — tampered CodeDirectory accepted";
            break;
        }

        // OpenSSL must specifically report a content-digest mismatch.
        if (failureReason != CMS_R_CONTENT_VERIFY_ERROR) {
            result = [NSString stringWithFormat:
                @"UNVERIFIED — unexpected negative-test error (%d)",
                failureReason];
            break;
        }

        result = @"PASS — CMS signature, SHA-256 cdhashes plist, V2 hash-agility and tamper rejection verified. Certificate trust remains UNVERIFIED.";
    } while (false);

    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return result;
}

bool CheckIfSigned(NSString *filePath) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		bool success = machO.CheckSignature();
		
		machO.Free();
		
		if (success) {
			gtimer.Print(">>> MachO is signed!");
			return true;
		} else {
			gtimer.Print(">>> MachO is not signed.");
			return false;
		}
	}
}

bool InjectDyLib(NSString *filePath, NSString *dylibPath, bool weakInject) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		std::string dylibPathStr = [dylibPath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		bool success = machO.InjectDylib(weakInject, dylibPathStr.c_str());
		
		machO.Free();
		
		if (success) {
			gtimer.Print(">>> Dylib injected successfully!");
			return true;
		} else {
			gtimer.Print(">>> Failed to inject dylib.");
			return false;
		}
	}
}

bool UninstallDylibs(NSString *filePath, NSArray<NSString *> *dylibPathsArray) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		std::set<std::string> dylibsToRemove;
		
		for (NSString *dylibPath in dylibPathsArray) {
			dylibsToRemove.insert([dylibPath UTF8String]);
		}
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		machO.RemoveDylib(dylibsToRemove);
		
		machO.Free();
		
		gtimer.Print(">>> Dylibs uninstalled successfully!");
		return true;
	}
}

NSArray<NSString *> *ListDylibs(NSString *filePath) {
	ZTimer gtimer;
	@autoreleasepool {
		NSMutableArray<NSString *> *dylibPathsArray = [NSMutableArray array];
		
		std::string filePathStr = [filePath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return nil;
		}
		
		std::vector<std::string> dylibPaths = machO.ListDylibs();
		
		if (!dylibPaths.empty()) {
			gtimer.Print(">>> List of dylibs in the Mach-O file:");
			for (const std::string &dylibPath : dylibPaths) {
				NSString *dylibPathStr = [NSString stringWithUTF8String:dylibPath.c_str()];
				[dylibPathsArray addObject:dylibPathStr];
			}
		} else {
			gtimer.Print(">>> No dylibs found in the Mach-O file.");
		}
		
		machO.Free();
		
		return [dylibPathsArray copy];
	}
}

bool ChangeDylibPath(NSString *filePath, NSString *oldPath, NSString *newPath) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		std::string oldPathStr = [oldPath UTF8String];
		std::string newPathStr = [newPath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		bool success = machO.ChangeDylibPath(oldPathStr.c_str(), newPathStr.c_str());
		
		machO.Free();
		
		if (success) {
			gtimer.Print(">>> Dylib path changed successfully!");
			return true;
		} else {
			gtimer.Print(">>> Failed to change dylib path.");
			return false;
		}
	}
}

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
	bool excludeprovion,
	bool sha256Only,
	void(^completionHandler)(BOOL success, NSError *error)
) {
	ZTimer atimer;
	ZTimer gtimer;
	
	bool bForce = true;
	bool bWeakInject = false;
	bool bAdhoc = adhoc;
	bool bSHA256Only = sha256Only;
	
	string strCertFile;
	string strPKeyFile;
	string strProvFile;
	string strPassword;
	string strBundleId;
	string strBundleVersion;
	string strDisplayName;
	string strEntitleFile;
	vector<string> arrDylibFiles;
	vector<string> arrDisDylibFiles;
	
	strPKeyFile = [key cStringUsingEncoding:NSUTF8StringEncoding];
	strProvFile = [prov cStringUsingEncoding:NSUTF8StringEncoding];
	strPassword = [pass cStringUsingEncoding:NSUTF8StringEncoding];
	strEntitleFile = [entitlement cStringUsingEncoding:NSUTF8StringEncoding];
	
	strBundleId = [bundleid cStringUsingEncoding:NSUTF8StringEncoding];
	strDisplayName = [displayname cStringUsingEncoding:NSUTF8StringEncoding];
	strBundleVersion = [bundleversion cStringUsingEncoding:NSUTF8StringEncoding];
	
	string strPath = [app cStringUsingEncoding:NSUTF8StringEncoding];
	if (!ZFile::IsFileExists(strPath.c_str())) {
		ZLog::ErrorV(">>> Invalid path! %s\n", strPath.c_str());
		return -1;
	}
	
	ZSignAsset zsa;
	if (!zsa.Init(strCertFile, strPKeyFile, strProvFile, strEntitleFile, strPassword, bAdhoc, bSHA256Only, false)) {
		return -1;
	}
	
	bool bEnableCache = true;
	string strFolder = strPath;
	
	atimer.Reset();
	ZBundle bundle;
	bool bRet = bundle.SignFolder(&zsa, strFolder, strBundleId, strBundleVersion, strDisplayName, arrDylibFiles, bForce, bWeakInject, bEnableCache, excludeprovion);
	ZLog::PrintV(">>> Signing:\t%s %s\n", strPath.c_str(), (bAdhoc ? " (Ad-hoc)" : ""));
	atimer.PrintResult(bRet, ">>> Signed %s!", bRet ? "OK" : "Failed");
	
	NSError* signError = nil;
	if(!bundle.signFailedFiles.empty()) {
		NSDictionary* userInfo = @{
			NSLocalizedDescriptionKey : [NSString stringWithUTF8String:bundle.signFailedFiles.c_str()]
		};
		signError = [NSError errorWithDomain:@"Failed to Sign" code:-1 userInfo:userInfo];
	}
	
	completionHandler(bRet, signError);
	
	gtimer.Print(">>> Done.");
	return bRet ? 0 : -1;
}


int checkCert(
	NSString *prov,
	NSString *key,
	NSString *pass,
	void(^completionHandler)(int status, NSDate* expirationDate, NSString *error)
) {
	ZTimer gtimer;
	
	string strCertFile;
	string strPKeyFile;
	string strProvFile;
	string strPassword;
	string strEntitleFile;
		
	if (!key || !prov || !pass) {
		completionHandler(2, nil, @"One or more required paths or password is missing.");
		return -1;
	}
		
	strPKeyFile = [key cStringUsingEncoding:NSUTF8StringEncoding];
	strProvFile = [prov cStringUsingEncoding:NSUTF8StringEncoding];
	strPassword = [pass cStringUsingEncoding:NSUTF8StringEncoding];

	__block ZSignAsset zsa;
		
	if (!zsa.Init(strCertFile, strPKeyFile, strProvFile, strEntitleFile, strPassword, false, false, false)) {
		completionHandler(2, nil, @"Unable to initialize certificate. Please check your password.");
		return -1;
	}
		
	X509* cert = (X509*)zsa.m_x509Cert;
	BIO *brother1;
	unsigned long issuerHash = X509_issuer_name_hash((X509*)cert);
	if (0x817d2f7a == issuerHash) {
		brother1 = BIO_new_mem_buf(ZSignAsset::s_szAppleDevCACert, (int)strlen(ZSignAsset::s_szAppleDevCACert));
	} else if (0x9b16b75c == issuerHash) {
		brother1 = BIO_new_mem_buf(ZSignAsset::s_szAppleDevCACertG3, (int)strlen(ZSignAsset::s_szAppleDevCACertG3));
	} else {
		completionHandler(2, nil, @"Unable to determine issuer of the certificate. It is signed by Apple Developer?");
		return -2;
	}
		
	if (!brother1)
	{
		completionHandler(2, nil, @"Unable to initialize issuer certificate.");
		return -3;
	}
		
	X509 *issuer = PEM_read_bio_X509(brother1, NULL, 0, NULL);
	
	if (!cert || !issuer) {
		completionHandler(2, nil, @"Error loading cert or issuer");
		return -4;
	}
	
	// Extract OCSP URL from cert
	STACK_OF(ACCESS_DESCRIPTION)* aia = (STACK_OF(ACCESS_DESCRIPTION)*)X509_get_ext_d2i((X509*)cert, NID_info_access, 0, 0);
	if (!aia) {
		completionHandler(2, nil, @"No AIA (OCSP) extension found in certificate");
		return -5;
	}
	
	ASN1_IA5STRING* uri = nullptr;
	for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if (OBJ_obj2nid(ad->method) == NID_ad_OCSP &&
			ad->location->type == GEN_URI) {
			uri = ad->location->d.uniformResourceIdentifier;
			
			break;
		}
	}
	
	if (!uri) {
		completionHandler(2, nil, @"No OCSP URI found in certificate.");
		return -6;
	}
	
	OCSP_REQUEST* req = OCSP_REQUEST_new();
	OCSP_CERTID* cert_id = OCSP_cert_to_id(nullptr, (X509*)cert, issuer);
	OCSP_request_add0_id(req, cert_id);  // Ownership transferred to request
	cert_id = OCSP_cert_to_id(nullptr, (X509*)cert, issuer);
	unsigned char* der = 0;
	int len = i2d_OCSP_REQUEST(req, &der);
	
	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithUTF8String:(const char *)uri->data]]];
	[request setHTTPMethod:@"POST"];
	[request setHTTPBody:[NSData dataWithBytes:der length:len]];
	[request setValue:@"application/ocsp-request" forHTTPHeaderField:@"Content-Type"];
	[request setValue:@"application/ocsp-response" forHTTPHeaderField:@"Accept"];
	
	OPENSSL_free(der);
	if (aia) {
		sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);
	}
	OCSP_REQUEST_free(req);
	X509_free(issuer);
	BIO_free(brother1);
	
	NSURLSession *session = [NSURLSession sharedSession];
	NSURLSessionDataTask *task = [session dataTaskWithRequest:request
											completionHandler:^(NSData * _Nullable data,
																NSURLResponse * _Nullable response,
																NSError * _Nullable error) {
		if (error) {
			completionHandler(2, nil, error.localizedDescription);
			return;
		}
		
		NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
		if (httpResponse.statusCode == 200 && data) {
			// You can save `data` or parse the response
			const void *respBytes = [data bytes];
			OCSP_RESPONSE *resp;
			d2i_OCSP_RESPONSE(&resp, (const unsigned char**)&respBytes, data.length);
			OCSP_BASICRESP *basic = OCSP_response_get1_basic(resp);
			ASN1_TIME *expirationDateAsn1 = X509_get_notAfter(cert);
			NSString *fullDateString = [NSString stringWithFormat:@"20%s", expirationDateAsn1->data];
			
			NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
			formatter.dateFormat = @"yyyyMMddHHmmss'Z'";
			formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
			formatter.locale = NSLocale.currentLocale;
			NSDate *expirationDate = [formatter dateFromString:fullDateString];
			
			int status, reason;
			if (OCSP_resp_find_status(basic, cert_id, &status, &reason, NULL, NULL, NULL)) {
				completionHandler(status, expirationDate, nil);
			} else {
				completionHandler(2, expirationDate, nil);
			}
			
			OCSP_CERTID_free(cert_id);
			OCSP_BASICRESP_free(basic);
			OCSP_RESPONSE_free(resp);
			
			
		} else {
			completionHandler(2, nil, @"Invalid response or no data");
			return;
		}
	}];
	
	[task resume];
	return 1;
}



}
