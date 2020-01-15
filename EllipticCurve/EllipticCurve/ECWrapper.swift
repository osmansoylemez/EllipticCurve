//
//  ECWrapper.swift
//  EllipticCurve
//
//  Created by Osman SÖYLEMEZ on 15.01.2020.
//  Copyright © 2020 Osman SÖYLEMEZ. All rights reserved.
//

import UIKit

@objc
public class ECWrapper: NSObject {
    
    struct Shared {
        
        static let keypair: EllipticCurveKeyPair.Manager = {
            EllipticCurveKeyPair.logger = { print($0) }
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: {
                return EllipticCurveKeyPair.Device.hasSecureEnclave ? [.userPresence, .privateKeyUsage] : [.userPresence]
            }())
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "no.agens.sign.public",
                privateLabel: "no.agens.sign.private",
                operationPrompt: "Sign transaction",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                token: .secureEnclaveIfAvailable)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }
    
    @objc public func getPublicKeyValue() -> String {
        var value = ""
        do {
            let key = try Shared.keypair.publicKey().data()
            value = key.PEM
        }
        catch {
        }
        return value
    }
    
    @objc public func sign(data:  String) -> String {
        
        var value = ""
        guard let digest = data.data(using: .utf8) else {
            return value
        }
        do {
            let signature = try Shared.keypair.sign(digest, hash: .sha256, context: nil)
            value = signature.base64EncodedString()
        }
        catch {
        }
        return value
    }
    
    @objc public func verify(data:  String, signature:  String) throws {
        
        guard let digest = data.data(using: .utf8) else {
            
        }
        
        guard let signatureDigest = data.data(using: .utf8) else {
        }
        
        try Shared.keypair.verify(signature: signatureDigest, originalDigest: digest, hash: .sha256)
    }
    
    @objc public func encrypt(data:  String) -> String {
        do {
            guard let input = data.data(using: .utf8) else {
                print("Missing/bad text in unencrypted text field")
            }
            guard #available(iOS 10.3, *) else {
                print("Can not encrypt on this device (must be iOS 10.3)")
            }
            let result = try Shared.keypair.encrypt(input)
            return result.base64EncodedString()
        } catch {
        }
        return ""
    }
    
    @objc public func decrypt(data:  String) -> String {
        
        do {
            guard let encrypted = Data(base64Encoded: data) else {
                print("Missing text in unencrypted text field")
            }
            
            let result = try Shared.keypair.decrypt(encrypted, context: nil)
            guard let decrypted = String(data: result, encoding: .utf8) else {
                print("Could not convert decrypted data to string")
            }
            
            return decrypted
        } catch {
        }
        return ""
    }
    
}
