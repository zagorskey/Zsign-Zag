//
//  Zsign.swift
//  Feather
//
//  Created by samara on 17.04.2025.
//

import Zsign

public enum Zsign {

    /// Apple Security basic X.509 policy, not installation authorization.
    static public func inspectAppleSecurityTrust(cms: Data) -> String {
        ZagInspectAppleSecurityTrust(cms)
    }

    /// Read-only X.509 chain check; does not establish installation authorization.
    static public func inspectCMSCertificateChain(cms: Data) -> String {
        ZagInspectCMSCertificateChain(cms)
    }

    /// Experimental cryptographic CMS check. Does not establish trust.
    static public func verifyDetachedCMS(
        cms: Data,
        codeDirectory: Data
    ) -> String {
        ZagVerifyDetachedCMS(cms, codeDirectory)
    }


	/// Checks if the MachO-file is properly signed
	/// - Parameter appExecutable: Executable
	/// - Returns: True if its signed
	static public func checkSigned(appExecutable: String) -> Bool {
		CheckIfSigned(appExecutable)
	}
	/// Injects a load command to an executable
	/// - Parameters:
	///   - appExecutable: Executable
	///   - path: Load command (i.e. `@rpath/CydiaSubstrate.framework`)
	///   - weak: Weak inject
	/// - Returns: True if its successful
	static public func injectDyLib(appExecutable: String, with path: String, weak: Bool = true) -> Bool {
		InjectDyLib(appExecutable, path, weak)
	}
	/// Removes load commands from an executable
	/// - Parameters:
	///   - appExecutable: Executable
	///   - dylibs: Load commands (i.e. `@rpath/CydiaSubstrate.framework...`)
	/// - Returns: True if its successful
	static public func removeDylibs(appExecutable: String, using dylibs: [String]) -> Bool  {
		UninstallDylibs(appExecutable, dylibs)
	}
	/// List load commands from an executable
	/// - Parameter appExecutable: Executable
	/// - Returns: String array with load commands if any
	static public func listDylibs(appExecutable: String) -> [String] {
		ListDylibs(appExecutable)
	}
	/// Matches and replaces load commands to an executable
	/// - Parameters:
	///   - appExecutable: Executable
	///   - old: Old load command (i.e. `/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate`)
	///   - new: New load command (i.e. `@rpath/CydiaSubstrate.framework/CydiaSubstrate`)
	/// - Returns: True if its successful
	static public func changeDylibPath(appExecutable: String, for old: String, with new: String) -> Bool {
		ChangeDylibPath(appExecutable, old, new)
	}
	/// Signs a folder (application bundle) using Zsign
	/// - Parameters:
	///   - appPath: Relative path to app bundle
	///   - provisionPath: Relative path to a provisioning file (i.e. `samara.mobileprovision`)
	///   - p12Path: Relative path to a key file (i.e. `samara.p12`)
	///   - p12Password: Password to the key file
	///   - entitlementsPath: Relative path to an entitlements file
	///   - customIdentifier: Custom indentifier for the app bundle
	///   - customName: Custom display name for the app bundle
	///   - customVersion: Custom version for the app bundle
	///   - adhoc: If the app bundle should be signed using Adhoc (no signing identity)
	///   - removeProvision: If `embedded.mobileprovision` should be excluded when signing
	/// - Returns: True if its successful
	static public func sign(
		appPath: String = "",
		provisionPath: String = "",
		p12Path: String = "",
		p12Password: String = "",
		entitlementsPath: String = "",
		customIdentifier: String = "",
		customName: String = "",
		customVersion: String = "",
		adhoc: Bool = false,
		removeProvision: Bool = false,
		sha256Only: Bool = false,
		completion: ((Bool, Error?) -> Void)? = nil
	) -> Bool {
		if zsign(
			appPath,
			provisionPath,
			p12Path,
			p12Password,
			entitlementsPath,
			customIdentifier,
			customName,
			customVersion,
			adhoc,
			removeProvision,
			sha256Only,
			completion.map { callback in
				{ success, error in
					callback(success, error)
				}
			}
		) != 0 {
			return false
		}
		return true
	}
	/// Strict signing for Apple Account certificates: the app (`""`) and each
	/// extension (`"PlugIns/X.appex"`) with its own profile and entitlements.
	/// The identity is `certificate` (DER) with either `keyData` (PEM, DER or
	/// PKCS #12, in memory) or `signer`, which signs a PKCS #1 DigestInfo
	/// (RSA PKCS #1 v1.5) so the private key need not leave its key store.
	/// Nested apps, App Clips, Watch apps, XPC services and extensions without
	/// a profile are refused. Every signed binary is verified afterwards.
	/// - Returns: nil when signed and verified; otherwise why not (the app
	///   must then be discarded).
	static public func signComponents(
		appPath: String,
		certificate: Data?,
		keyData: Data? = nil,
		keyPassword: String = "",
		signer: ((Data) -> Data?)? = nil,
		components: [String: (provision: Data, entitlements: Data)],
		bundleIdentifier: String? = nil,
		extraIntermediates: [Data] = []
	) -> String? {
		var error: NSString?
		let input = components.mapValues { ["provision": $0.provision, "entitlements": $0.entitlements] as [String: Data] }
		let ok = ZagSignComponents(
			appPath, certificate, keyData, keyPassword,
			signer.map { sign in { digestInfo in digestInfo.flatMap(sign) } },
			input, bundleIdentifier, extraIntermediates, &error
		)
		return ok ? nil : (error as String? ?? "Signing failed.")
	}

	/// Re-checks an app signed by `signComponents`, without changing it:
	/// every binary's signature, code hashes, team, identifiers, entitlements
	/// and embedded profiles. Returns nil when it verifies.
	static public func verifyComponents(
		appPath: String,
		certificate: Data,
		components: [String: (provision: Data, entitlements: Data)]
	) -> String? {
		var error: NSString?
		let input = components.mapValues { ["provision": $0.provision, "entitlements": $0.entitlements] as [String: Data] }
		return ZagVerifyComponents(appPath, certificate, input, &error) ? nil : (error as String? ?? "Not verified.")
	}

	/// Check revokage
	/// - Parameters:
	///   - provisionPath: Relative path to a provisioning file (i.e. `samara.mobileprovision`)
	///   - p12Path: Relative path to a key file (i.e. `samara.p12`)
	///   - p12Password: Password to the key file
	///   - completionHandler: Handler
	static public func checkRevokage(
		provisionPath: String = "",
		p12Path: String = "",
		p12Password: String = "",
		completionHandler: @escaping (Int32, Date?, String?) -> Void
	) {
		checkCert(
			provisionPath,
			p12Path,
			p12Password
		) { status, expirationDate, error in
			completionHandler(status, expirationDate, error)
		}
	}
}
