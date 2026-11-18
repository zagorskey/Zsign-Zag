import Foundation
import Security
import Zsign

// Strict signing, end to end on synthetic input. Each signed result is also
// checked independently: codesign reads it, OpenSSL verifies each CMS
// signature over its code directory, and the app's seal covers the
// extension as signed (so extensions are signed before the app).

let env = ProcessInfo.processInfo.environment
let openssl = env["ZAG_OPENSSL"]!
let pki = URL(fileURLWithPath: env["ZAG_PKI"]!)
let bin = URL(fileURLWithPath: env["ZAG_BIN"]!)
let work = URL(fileURLWithPath: env["ZAG_WORK"]!)
let team = "TESTTEAM01"
let appID = "com.example.zagtest"

func data(_ name: String) -> Data { try! Data(contentsOf: pki.appendingPathComponent(name)) }
let intermediate = data("test.der")

@discardableResult
func run(_ tool: String, _ arguments: [String]) -> (status: Int32, output: String) {
	let process = Process()
	process.executableURL = URL(fileURLWithPath: tool)
	process.arguments = arguments
	let pipe = Pipe()
	process.standardOutput = pipe
	process.standardError = pipe
	try! process.run()
	let output = pipe.fileHandleForReading.readDataToEndOfFile()
	process.waitUntilExit()
	return (process.terminationStatus, String(decoding: output, as: UTF8.self))
}

func plist(_ value: Any) -> Data { try! PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0) }

/// A profile signed (CMS) by the test authority, as Apple signs real ones.
func profile(bundle: String, team profileTeam: String = team, certificates: [Data] = [data("good.der")],
			 entitlements extra: [String: Any] = [:], expires: Date = Date(timeIntervalSinceNow: 7 * 86_400)) -> Data {
	var entitlements: [String: Any] = [
		"application-identifier": "\(profileTeam).\(bundle)",
		"com.apple.developer.team-identifier": profileTeam,
		"get-task-allow": true,
		"keychain-access-groups": ["\(profileTeam).*"]
	]
	entitlements.merge(extra) { $1 }
	let body: [String: Any] = [
		"AppIDName": bundle, "TeamIdentifier": [profileTeam], "TeamName": "Zag Test", "Name": bundle,
		"UUID": UUID().uuidString, "CreationDate": Date(), "ExpirationDate": expires, "Version": 1,
		"DeveloperCertificates": certificates, "Entitlements": entitlements, "ProvisionedDevices": ["00000000-0000000000000000"]
	]
	let input = work.appendingPathComponent("p-\(UUID().uuidString).plist"), output = work.appendingPathComponent("p-\(UUID().uuidString).der")
	try! plist(body).write(to: input)
	let result = run(openssl, ["cms", "-sign", "-nodetach", "-binary", "-outform", "DER", "-signer", pki.appendingPathComponent("test.pem").path,
							   "-inkey", pki.appendingPathComponent("test.key").path, "-in", input.path, "-out", output.path])
	precondition(result.status == 0, result.output)
	return try! Data(contentsOf: output)
}

func entitlements(_ bundle: String, _ extra: [String: Any] = [:]) -> Data {
	var value: [String: Any] = [
		"application-identifier": "\(team).\(bundle)",
		"com.apple.developer.team-identifier": team,
		"get-task-allow": true,
		"keychain-access-groups": ["\(team).\(bundle)"]
	]
	value.merge(extra) { $1 }
	return plist(value)
}

/// An app with a widget extension, a framework and a library.
func makeApp(widget: Bool = true, extra: [String] = [], widgetID: String = "\(appID).widget") -> URL {
	let app = work.appendingPathComponent("apps/\(UUID().uuidString)/Zag.app")
	func bundle(_ url: URL, _ id: String, _ exe: String, _ type: String, binary: URL) {
		try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
		try! plist(["CFBundleIdentifier": id, "CFBundleExecutable": exe, "CFBundleName": exe, "CFBundleVersion": "1",
					"CFBundleShortVersionString": "1.0", "CFBundlePackageType": type, "MinimumOSVersion": "16.4"]).write(to: url.appendingPathComponent("Info.plist"))
		try! FileManager.default.copyItem(at: binary, to: url.appendingPathComponent(exe))
	}
	bundle(app, appID, "Zag", "APPL", binary: bin.appendingPathComponent("exe"))
	bundle(app.appendingPathComponent("Frameworks/Kit.framework"), "\(appID).kit", "Kit", "FMWK", binary: bin.appendingPathComponent("Kit"))
	try! FileManager.default.copyItem(at: bin.appendingPathComponent("libzag.dylib"), to: app.appendingPathComponent("Frameworks/libzag.dylib"))
	if widget {
		bundle(app.appendingPathComponent("PlugIns/Widget.appex"), widgetID, "Widget", "XPC!", binary: bin.appendingPathComponent("exe"))
	}
	for path in extra {
		bundle(app.appendingPathComponent(path), "\(appID).extra", "Extra", path.hasSuffix(".appex") ? "XPC!" : "APPL", binary: bin.appendingPathComponent("exe"))
	}
	return app
}

typealias Components = [String: (provision: Data, entitlements: Data)]

func makeParts(widget: Bool = true) -> Components {
	var value: Components = ["": (profile(bundle: appID), entitlements(appID))]
	if widget { value["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget"), entitlements("\(appID).widget")) }
	return value
}

func sign(_ app: URL, _ parts: Components, certificate: Data? = data("good.der"), key: Data? = data("good.key"),
		  signer: ((Data) -> Data?)? = nil, intermediates: [Data] = [intermediate], bundleID: String? = nil) -> String? {
	Zsign.signComponents(appPath: app.path, certificate: certificate, keyData: signer == nil ? key : nil, signer: signer,
						 components: parts, bundleIdentifier: bundleID, extraIntermediates: intermediates)
}

/// Every file in the bundle, for checking that a refused request changed nothing.
func snapshot(_ app: URL) -> [String: Data] {
	var files: [String: Data] = [:]
	for case let url as URL in FileManager.default.enumerator(at: app, includingPropertiesForKeys: nil)! {
		if let contents = try? Data(contentsOf: url) { files[url.path] = contents }
	}
	return files
}

/// The CMS signature and code directory of a binary, checked by OpenSSL.
func opensslVerifies(_ binary: URL, signer expected: Data) -> Bool {
	let bytes = try! Data(contentsOf: binary)
	guard let (cms, cd) = signatureBlobs(bytes) else { return false }
	let cmsFile = work.appendingPathComponent("cms-\(UUID().uuidString)"), cdFile = work.appendingPathComponent("cd-\(UUID().uuidString)")
	let signerFile = work.appendingPathComponent("signer-\(UUID().uuidString).pem")
	try! cms.write(to: cmsFile); try! cd.write(to: cdFile)
	let verify = run(openssl, ["cms", "-verify", "-binary", "-inform", "DER", "-in", cmsFile.path, "-content", cdFile.path,
							   "-noverify", "-signer", signerFile.path, "-out", "/dev/null"])
	let der = run(openssl, ["x509", "-in", signerFile.path, "-outform", "DER", "-out", signerFile.path + ".der"])
	return verify.status == 0 && der.status == 0 && (try? Data(contentsOf: URL(fileURLWithPath: signerFile.path + ".der"))) == expected
}

func be32(_ d: Data, _ o: Int) -> Int { d[o..<o + 4].reduce(0) { $0 << 8 | Int($1) } }
func le32(_ d: Data, _ o: Int) -> Int { d[o..<o + 4].reversed().reduce(0) { $0 << 8 | Int($1) } }

func signatureBlobs(_ d: Data) -> (cms: Data, cd: Data)? {
	let d = Data(d)
	guard le32(d, 0) == 0xfeedfacf else { return nil }
	var offset = 32
	for _ in 0..<le32(d, 16) {
		if le32(d, offset) == 0x1d {
			let base = le32(d, offset + 8)
			var blobs: [Int: Data] = [:]
			for i in 0..<be32(d, base + 8) {
				let type = be32(d, base + 12 + i * 8), at = base + be32(d, base + 16 + i * 8)
				blobs[type] = d[at..<at + be32(d, at + 4)]
			}
			guard let cms = blobs[0x10000], let cd = blobs[0] else { return nil }
			return (Data(cms.dropFirst(8)), Data(cd))
		}
		offset += le32(d, offset + 4)
	}
	return nil
}

func entitlementsBlob(_ binary: URL) -> [String: Any] {
	let d = try! Data(contentsOf: binary)
	var offset = 32
	for _ in 0..<le32(d, 16) {
		if le32(d, offset) == 0x1d {
			let base = le32(d, offset + 8)
			for i in 0..<be32(d, base + 8) where be32(d, base + 12 + i * 8) == 5 {
				let at = base + be32(d, base + 16 + i * 8)
				let blob = d[(at + 8)..<(at + be32(d, at + 4))]
				return (try? PropertyListSerialization.propertyList(from: Data(blob), format: nil)) as? [String: Any] ?? [:]
			}
		}
		offset += le32(d, offset + 4)
	}
	return [:]
}

/// A Security framework key (from the test key's PKCS #1 bytes) that signs
/// DigestInfo blocks, as a Keychain key would on the device.
func securitySigner(_ keyFile: String, calls: UnsafeMutablePointer<Int>) -> (Data) -> Data? {
	let key = SecKeyCreateWithData(data(keyFile) as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil)!
	return { digestInfo in
		calls.pointee += 1
		return SecKeyCreateSignature(key, .rsaSignatureDigestPKCS1v15Raw, digestInfo as CFData, nil) as Data?
	}
}

@main struct Tests {
	static var passed = 0
	static func check(_ value: Bool, _ label: String) {
		guard value else { fatalError("FAIL: \(label)") }
		passed += 1
		print("PASS: \(label)")
	}

	static func main() {
		setvbuf(stdout, nil, _IOLBF, 0)
		legitimate()
		rawSigner()
		identities()
		componentChecks()
		structure()
		malformed()
		print("SUCCESS: \(passed) strict signing checks passed")
	}

	static func legitimate() {
		let app = makeApp(), parts = makeParts()
		check(sign(app, parts) == nil, "an app with an extension, a framework and a library is signed")
		let widget = app.appendingPathComponent("PlugIns/Widget.appex")
		let main = run("/usr/bin/codesign", ["-dvvv", app.path]).output, ext = run("/usr/bin/codesign", ["-dvvv", widget.path]).output
		check(main.contains("Identifier=\(appID)") && main.contains("TeamIdentifier=\(team)")
			  && ext.contains("Identifier=\(appID).widget") && ext.contains("TeamIdentifier=\(team)"),
			  "codesign reads each bundle's own identifier and the team")
		for binary in [app.appendingPathComponent("Zag"), widget.appendingPathComponent("Widget"),
					   app.appendingPathComponent("Frameworks/Kit.framework/Kit"), app.appendingPathComponent("Frameworks/libzag.dylib")] {
			check(opensslVerifies(binary, signer: data("good.der")), "OpenSSL verifies \(binary.lastPathComponent)'s CMS signature, by the identity's certificate")
		}
		check(entitlementsBlob(app.appendingPathComponent("Zag"))["application-identifier"] as? String == "\(team).\(appID)"
			  && entitlementsBlob(widget.appendingPathComponent("Widget"))["application-identifier"] as? String == "\(team).\(appID).widget"
			  && entitlementsBlob(app.appendingPathComponent("Frameworks/Kit.framework/Kit")).isEmpty,
			  "the app and the extension each carry their own entitlements; the framework none")
		check((try? Data(contentsOf: widget.appendingPathComponent("embedded.mobileprovision"))) == parts["PlugIns/Widget.appex"]!.provision
			  && (try? Data(contentsOf: app.appendingPathComponent("embedded.mobileprovision"))) == parts[""]!.provision,
			  "each bundle embeds its own profile")
		let seal = (try? PropertyListSerialization.propertyList(from: Data(contentsOf: app.appendingPathComponent("_CodeSignature/CodeResources")), format: nil)) as? [String: Any]
		let sealed = ((seal?["files2"] as? [String: Any])?["PlugIns/Widget.appex/Widget"] as? [String: Any])?["hash2"] as? Data
		let actual = run("/usr/bin/shasum", ["-a", "256", widget.appendingPathComponent("Widget").path]).output.prefix(64)
		check(sealed.map { $0.map { String(format: "%02x", $0) }.joined() } == String(actual), "the app's seal covers the extension as signed (nested bundles first)")
		check(Zsign.verifyComponents(appPath: app.path, certificate: data("good.der"), components: parts) == nil, "the result verifies independently")

		var tampered = try! Data(contentsOf: widget.appendingPathComponent("Widget"))
		tampered[0x4000 - 1] ^= 0xff
		try! tampered.write(to: widget.appendingPathComponent("Widget"))
		let error = Zsign.verifyComponents(appPath: app.path, certificate: data("good.der"), components: parts) ?? ""
		check(error.contains("PlugIns/Widget.appex") && error.contains("does not match"), "a changed byte of code is found")

		let renamed = makeApp()
		var newParts: Components = ["": (profile(bundle: "com.example.renamed"), entitlements("com.example.renamed")),
									"PlugIns/Widget.appex": (profile(bundle: "com.example.renamed.widget"), entitlements("com.example.renamed.widget"))]
		check(sign(renamed, newParts, bundleID: "com.example.renamed") == nil
			  && run("/usr/bin/codesign", ["-dvvv", renamed.appendingPathComponent("PlugIns/Widget.appex").path]).output.contains("Identifier=com.example.renamed.widget"),
			  "with a new bundle ID, the extension's ID follows and matches its profile")
		newParts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget"), entitlements("\(appID).widget"))
		check(sign(makeApp(), newParts, bundleID: "com.example.renamed")?.contains("another App ID") == true,
			  "a profile for the extension's old ID is refused after renaming")
	}

	static func rawSigner() {
		var calls = 0
		let app = makeApp(), parts = makeParts()
		let error = sign(app, parts, key: nil, signer: securitySigner("good.pkcs1.der", calls: &calls))
		check(error == nil && calls >= 4, "a Security framework key signs through the callback (no key data given to Zsign)")
		check(opensslVerifies(app.appendingPathComponent("Zag"), signer: data("good.der"))
			  && Zsign.verifyComponents(appPath: app.path, certificate: data("good.der"), components: parts) == nil,
			  "the callback's signatures verify")

		var otherCalls = 0
		let wrong = sign(makeApp(), parts, key: nil, signer: securitySigner("other.pkcs1.der", calls: &otherCalls)) ?? ""
		check(wrong.contains("did not verify"), "signatures from another key are caught by the output check")
		check(sign(makeApp(), parts, key: nil, signer: { _ in nil })?.contains("Signing failed") == true, "a signer that refuses fails the signing")
		check(sign(makeApp(), parts, key: nil, signer: { _ in Data(count: 16) })?.contains("Signing failed") == true, "a malformed signature fails the signing")
		check(sign(makeApp(), parts, certificate: nil, key: nil, signer: { _ in nil })?.contains("needs its certificate") == true, "a signer needs its certificate")
	}

	static func identities() {
		let parts = makeParts()
		let fake = sign(makeApp(widget: false), ["": (profile(bundle: appID, certificates: [data("fake.der")]), entitlements(appID))],
						certificate: data("fake.der"), key: data("fake.key"), intermediates: []) ?? ""
		check(fake.contains("not issued by a supported Apple"), "a certificate whose issuer is merely named like Apple's intermediate is refused")
		let noIntermediate = sign(makeApp(), parts, intermediates: []) ?? ""
		check(noIntermediate.contains("not issued by a supported Apple"), "an unknown issuer is refused before signing")
		let expired = sign(makeApp(widget: false), ["": (profile(bundle: appID, certificates: [data("expired.der")]), entitlements(appID))],
						   certificate: data("expired.der"), key: data("expired.key")) ?? ""
		check(expired.contains("expired"), "an expired certificate is refused")
		let noEKU = sign(makeApp(widget: false), ["": (profile(bundle: appID, certificates: [data("noeku.der")]), entitlements(appID))],
						 certificate: data("noeku.der"), key: data("noeku.key")) ?? ""
		check(noEKU.contains("code signing"), "a certificate not for code signing is refused")
		check(sign(makeApp(), parts, key: data("other.key"))?.contains("not for this key") == true, "a key that is not the certificate's is refused")
		check(sign(makeApp(), parts, certificate: nil) == nil, "with a key only, the profile's certificate for it is used")
		check(sign(makeApp(), parts, key: Data("not a key".utf8))?.contains("cannot be read") == true, "unreadable key data is refused")
	}

	static func componentChecks() {
		func refused(_ parts: Components, _ text: String, _ label: String, app: URL = makeApp()) {
			let before = snapshot(app)
			let error = sign(app, parts) ?? ""
			check(error.contains(text) && snapshot(app) == before, label + " (nothing is changed)")
		}
		var parts = makeParts()
		parts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).other"), entitlements("\(appID).widget"))
		refused(parts, "another App ID", "an extension profile for another App ID is refused")
		parts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget", team: "OTHERTEAM1"), entitlements("\(appID).widget"))
		refused(parts, "another team", "an extension profile for another team is refused")
		parts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget", certificates: [data("other.der")]), entitlements("\(appID).widget"))
		refused(parts, "does not include the signing certificate", "an extension profile without the signing certificate is refused")
		parts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget", expires: Date(timeIntervalSinceNow: -60)), entitlements("\(appID).widget"))
		refused(parts, "expired", "an expired extension profile is refused")
		parts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget"), entitlements("\(appID).widget", ["aps-environment": "development"]))
		refused(parts, "does not allow aps-environment", "an entitlement the profile does not allow is refused")
		parts["PlugIns/Widget.appex"] = (profile(bundle: "\(appID).widget"), entitlements(appID))
		refused(parts, "entitlements are for another App ID", "extension entitlements for the app's App ID are refused")
		parts = makeParts()
		parts[""] = (profile(bundle: appID), entitlements(appID, ["com.apple.developer.team-identifier": "OTHERTEAM1"]))
		refused(parts, "the entitlements are for another team", "entitlements naming another team are refused")
		parts = makeParts(widget: false)
		refused(parts, "no provisioning profile for this extension", "an extension without a profile is refused")
		refused(makeParts(), "must start with the app's", "an extension whose ID does not extend the app's is refused",
				app: makeApp(widgetID: "com.example.unrelated.widget"))
		parts = makeParts()
		parts["PlugIns/Missing.appex"] = parts["PlugIns/Widget.appex"]
		refused(parts, "not an extension in this app", "a profile for an extension that is not there is refused")
	}

	static func structure() {
		for (path, text) in [("Watch/Zag Watch.app", "Apple Watch apps are not supported"), ("AppClips/Clip.app", "App Clips are not supported"),
							 ("XPCServices/Helper.xpc", "XPC services are not supported"), ("PlugIns/Widget.appex/PlugIns/Inner.appex", "inside other bundles"),
							 ("Nested.app", "nested apps are not supported")] {
			let app = makeApp(extra: [path]), before = snapshot(app)
			let error = sign(app, makeParts()) ?? ""
			check(error.contains(text) && snapshot(app) == before, "\(path): \(text) (nothing is changed)")
		}
	}

	static func malformed() {
		let broken = makeApp()
		try! Data("not a Mach-O".utf8).write(to: broken.appendingPathComponent("Frameworks/libzag.dylib"))
		check(sign(broken, makeParts())?.contains("Signing failed") == true, "a library that cannot be signed fails the whole app")
		let badExe = makeApp()
		try! Data("not a Mach-O".utf8).write(to: badExe.appendingPathComponent("PlugIns/Widget.appex/Widget"))
		check(sign(badExe, makeParts())?.contains("Signing failed") == true, "an extension executable that cannot be signed fails the app")
		check(sign(makeApp(widget: false), ["": (Data("garbage".utf8), entitlements(appID))])?.contains("cannot be read") == true, "an unreadable profile is refused")
		check(sign(makeApp(widget: false), ["": (profile(bundle: appID), Data())])?.contains("No entitlements") == true, "missing entitlements are refused")
		check(sign(work.appendingPathComponent("missing.app"), makeParts())?.contains("Not an app") == true, "a missing app is refused")

		// The original entry point no longer reports success for a certificate
		// it cannot make a signature with (it used to print "Signed OK!").
		let legacy = makeApp(widget: false)
		let profileFile = work.appendingPathComponent("legacy.mobileprovision"), keyFile = pki.appendingPathComponent("fake.key")
		try! profile(bundle: appID, certificates: [data("fake.der")]).write(to: profileFile)
		var reported: Bool?
		let result = Zsign.sign(appPath: legacy.path, provisionPath: profileFile.path, p12Path: keyFile.path, removeProvision: true) { ok, _ in reported = ok }
		check(!result && reported != true, "the original entry point fails instead of reporting an unsigned app as signed")
	}
}
