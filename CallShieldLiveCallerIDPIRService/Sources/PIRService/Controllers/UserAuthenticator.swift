// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Crypto
import Foundation

private enum SignedUserToken {
    static let signingSecretEnvironmentKey = "LIVE_CALLER_ID_USER_TOKEN_SIGNING_SECRET"
    static let expectedBundleID = "com.almorantino.callshield"
    static let expectedExtensionID = "com.almorantino.callshield.CallShieldLiveCallerID"
    static let versionPrefix = "v1"

    struct Payload: Decodable {
        let v: Int
        let tier: UserTier
        let bundle_id: String
        let extension_id: String
        let exp: Int
    }
}

actor UserAuthenticator: UserTokenAuthenticator {
    var allowList: [String: UserTier]
    let signedTokenSecret: String?

    init() {
        self.allowList = [:]
        self.signedTokenSecret = ProcessInfo.processInfo.environment[SignedUserToken.signingSecretEnvironmentKey]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .nilIfEmpty
    }

    func add(token: String, tier: UserTier) {
        allowList[token] = tier
    }

    func authenticate(userToken: String) async throws -> UserTier? {
        if let userTier = allowList[userToken] {
            return userTier
        }

        return authenticateSignedToken(userToken)
    }

    func update(allowList: [String: UserTier]) {
        self.allowList = allowList
    }

    private func authenticateSignedToken(_ userToken: String) -> UserTier? {
        let candidateTokens = [userToken, userToken.base64DecodedString].compactMap(\.self)
        guard
            let signedTokenSecret,
            let payload = candidateTokens.lazy.compactMap({ self.signedPayload(from: $0, secret: signedTokenSecret) }).first,
            payload.v == 1,
            payload.bundle_id == SignedUserToken.expectedBundleID,
            payload.extension_id == SignedUserToken.expectedExtensionID,
            payload.exp > Int(Date().timeIntervalSince1970)
        else {
            return nil
        }

        return payload.tier
    }

    private func signedPayload(from userToken: String, secret: String) -> SignedUserToken.Payload? {
        let parts = userToken.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              parts[0] == SignedUserToken.versionPrefix,
              let signature = String(parts[2]).base64URLDecodedData
        else {
            return nil
        }

        let signingInput = "\(parts[0]).\(parts[1])"
        let key = SymmetricKey(data: Data(secret.utf8))
        guard HMAC<SHA256>.isValidAuthenticationCode(
            signature,
            authenticating: Data(signingInput.utf8),
            using: key)
        else {
            return nil
        }

        guard let payloadData = String(parts[1]).base64URLDecodedData else {
            return nil
        }
        return try? JSONDecoder().decode(SignedUserToken.Payload.self, from: payloadData)
    }
}

private extension String {
    var base64URLDecodedData: Data? {
        var base64 = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: padding))
        return Data(base64Encoded: base64)
    }

    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }

    var base64DecodedString: String? {
        var base64 = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: padding))
        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
