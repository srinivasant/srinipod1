//
//  oAuthManager.swift
//  srinipod11
//
//  Created by Srinivasan T on 01/08/22.
//

import Foundation
import AuthenticationServices
import os

extension NSNotification.Name {
    static let UserSignIn = Notification.Name("UserSignInNotification")
    static let UserRegisterIn = Notification.Name("UserRegisterInNotification")
    static let UserErrIn = Notification.Name("UserErrInNotification")

}

class AccountManager: NSObject, ASAuthorizationControllerPresentationContextProviding, ASAuthorizationControllerDelegate {
    var authenticationAnchor: ASPresentationAnchor?

    func signInWith(anchor: ASPresentationAnchor,relyingParty:String,challengeStr:String) {
        let domain =  relyingParty//"webauth.legalastra.com"

        self.authenticationAnchor = anchor
        let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)

        // Fetch the challenge the server. The challengs should be unique for every request.
        var challenge = Data()
        let challenge1 = challengeStr //"SigninChallenge"
         challenge = Data(challenge1.utf8)
        print("challenge ==>\(challenge)")
        let assertionRequest = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: challenge)

        // Also allow the user to used a saved password, if they have one.
        let passwordCredentialProvider = ASAuthorizationPasswordProvider()
        let passwordRequest = passwordCredentialProvider.createRequest()

        // Pass in any mix of supported sign in request types.
        let authController = ASAuthorizationController(authorizationRequests: [ assertionRequest, passwordRequest ] )
        authController.delegate = self
        authController.presentationContextProvider = self
        authController.performRequests()
    }
    
    func signUpWith(userName: String,relyingParty:String,challengeStr:String, anchor: ASPresentationAnchor) {
        let domain =  relyingParty//"webauth.legalastra.com"

        self.authenticationAnchor = anchor
        let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)

        // Fetch the challenge the server. The challengs should be unique for every request.
        // The userID is the identifier for the user's account.
        var challenge = Data()

        let challenge1 = challengeStr//"RegisterChallenge"
        challenge = Data(challenge1.utf8)
        let decodeString = String(decoding: challenge, as: UTF8.self)
        print("Decode challenge \(decodeString)")
        let deviceID = UIDevice.current.identifierForVendor?.uuidString ?? ""
        let userID = Data(deviceID.utf8)

        let registrationRequest = publicKeyCredentialProvider.createCredentialRegistrationRequest(challenge: challenge,
                                                                                                  name: userName, userID:userID)
        
       // let registrationRequest = publicKeyCredentialProvider.
        // Only ASAuthorizationPlatformPublicKeyCredentialRegistrationRequests or
        // ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequests should be used here.
        let authController = ASAuthorizationController(authorizationRequests: [ registrationRequest ] )
        authController.delegate = self
        authController.presentationContextProvider = self
        authController.performRequests()
    }
    
    func base64ToBase64url(base64: String) -> String {
        let base64url = base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return base64url
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        let logger = Logger()
        switch authorization.credential {
        case let credentialRegistration as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            logger.log("A new credential was registered: \(credentialRegistration)")
//            if let json = try JSONSerialization.jsonObject(with: credentialRegistration, options: .mutableContainers) as? NSDictionary {
//                print("json object \(json)")
//            }

            let credentialID = credentialRegistration.credentialID.base64EncodedString()
            let base64Id = base64ToBase64url(base64: credentialID)
            let attestationObject = credentialRegistration.rawAttestationObject!
            let rawClientDataJSON = credentialRegistration.rawClientDataJSON
//            print("credentialID \(credentialID.base64EncodedString().utf8)")
//            print("attestationObject \(attestationObject)")
//            print("rawClientDataJSON \(rawClientDataJSON.base64EncodedData())")
            
            let data: Data = rawClientDataJSON
            if let string = String(data: data, encoding: .utf8) {
                print(" RegClientDataJSON  ==> \(string)")
            } else {
                print("not a valid UTF-8 sequence")
            }
            let parameter1 = [
                "attestationObject" :attestationObject.base64EncodedString(),
                "clientDataJSON": rawClientDataJSON.base64EncodedString(),
                ] as NSDictionary
            let parameter2 = [:
                ] as NSDictionary
//            let c_data = String()
//            let cred_data: Data = credentialID
//            if let c_data = String(data: cred_data, encoding: .) {
//                print(" ClientDataJSON  ==> \(c_data)")
//            } else {
//                print("not a valid UTF-8 sequence")
//            }

            let parameters = [
                "user_id" : UIDevice.current.identifierForVendor?.uuidString ?? "",
                "id" :base64Id,
                "rawId":base64Id,
                "response":parameter1,
                "type": "public-key",
                "clientExtensionResults": parameter2,
                "transports": [
                    "internal"
                  ]
                ] as NSDictionary
            print("Register response ==> \(parameters)")
            UserDefaults.standard.setValue(parameters, forKey: "response")
            let data1: Data = attestationObject
            if let string = String(data: data1, encoding: .utf8) {
                print(" attestationObject  ==> \(string)")
            } else {
                print("not a valid UTF-8 sequence")
            }
            
        

            // Verify the attestationObject and clientDataJSON with your service.
            // The attestationObject contains the user's new public key, which should be stored and used for subsequent sign ins.
            // let attestationObject = credentialRegistration.rawAttestationObject
            // let N/. = credentialRegistration.rawClientDataJSON
            
            // clientdataJSON --> Challenge,origin,type
            // attestationObject -->AuthData,attestationFormat,attestationStatement
            //attestationStatement --> Signature,x5c(attestation certificate)
            //AuthData --> credencial id length,credencial id,publickey object
            // After the server has verified the registration and created the user account, sign the user in with the new account.
            didFinishRegister()
        case let credentialAssertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            logger.log("A credential was used to authenticate: \(credentialAssertion)")
            let authenticatorData = credentialAssertion.rawAuthenticatorData
            let userID = credentialAssertion.userID.base64EncodedString()
            let attestationSignature = credentialAssertion.signature
            let rawClientDataJSON = credentialAssertion.rawClientDataJSON
            print("rawClientDataJSON response ==> \(rawClientDataJSON)")

            print(" userID  ==> \(userID)")
            print(" signature  ==> \(attestationSignature)")
            let data: Data = rawClientDataJSON
            if let string = String(data: data, encoding: .utf8) {
                print(" SigninClientDataJSON  ==> \(string)")
            } else {
                print("not a valid UTF-8 sequence")
            }
            
            let credentialID = credentialAssertion.credentialID.base64EncodedString()
            let base64Id = base64ToBase64url(base64: credentialID)
            let signatureId = base64ToBase64url(base64: attestationSignature!.base64EncodedString())
            let authenticatorDataID = base64ToBase64url(base64: authenticatorData!.base64EncodedString())

            let parameter1 = [
                "authenticatorData" :authenticatorDataID,
                "clientDataJSON":rawClientDataJSON.base64EncodedString(),
                "signature":signatureId,
                "userHandle":userID
                ] as NSDictionary
            let parameter2 = [:
                ] as NSDictionary
            let parameters = [
                "user_id" : UIDevice.current.identifierForVendor?.uuidString ?? "",
                "id" : base64Id,
                "rawId":base64Id,
                "response":parameter1,
                "type": "public-key",
                "clientExtensionResults": parameter2,
                ] as NSDictionary
            print("Signin response ==> \(parameters)")

            UserDefaults.standard.setValue(parameters, forKey: "signResponse")
            // Verify the below signature and clientDataJSON with your service for the given userID.
            // let signature = credentialAssertion.signature
            // let clientDataJSON = credentialAssertion.rawClientDataJSON
            // let userID = credentialAssertion.userID

            // After the server has verified the assertion, sign the user in.
            didFinishSignIn()
        case let passwordCredential as ASPasswordCredential:
            logger.log("A passwordCredential was provided: \(passwordCredential)")
            // Verify the userName and password with your service.
            // let userName = passwordCredential.user
            // let password = passwordCredential.password

            // After the server has verified the userName and password, sign the user in.
            didFinishSignIn()
        default:
            fatalError("Received unknown authorization type.")
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        let logger = Logger()
        guard let authorizationError = ASAuthorizationError.Code(rawValue: (error as NSError).code) else {
            UserDefaults.standard.setValue("\(error.localizedDescription)", forKey: "regError")
            didFinishError()
            logger.error("Unexpected authorization error: \(error.localizedDescription)")
            return
        }

        if authorizationError == .canceled {
            // Either no credentials were found and the request silently ended, or the user canceled the request.
            // Consider asking the user to create an account.
            UserDefaults.standard.setValue("\(error.localizedDescription)", forKey: "regError")
            didFinishError()
            logger.log("Request canceled.")
        } else {
            // Other ASAuthorization error.
            // The userInfo dictionary should contain useful information.
            UserDefaults.standard.setValue("\(error.localizedDescription)", forKey: "regError")
            didFinishError()
            logger.error("Error: \((error as NSError).userInfo)")
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return authenticationAnchor!
    }

    func didFinishSignIn() {
        NotificationCenter.default.post(name: .UserSignIn, object: nil)
    }
    
    func didFinishRegister() {
        NotificationCenter.default.post(name: .UserRegisterIn, object: nil)
    }
    
    func didFinishError() {
        NotificationCenter.default.post(name: .UserErrIn, object: nil)
    }
}

