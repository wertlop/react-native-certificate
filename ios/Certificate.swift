import Foundation
import SwiftyRSA
import CryptoSwift
import SwiftDate
import ASN1Decoder
import SwiftyJSON

extension Data {
    var bytes : [UInt8]{
        return [UInt8](self)
    }
}

extension Array where Element == UInt8 {
    var data : Data{
        return Data(self)
    }
}

extension String {
    mutating func removingRegexMatches(pattern: String, replaceWith: String = "") {
        do {
            let regex = try NSRegularExpression(pattern: pattern, options: .caseInsensitive)
            let range = NSRange(location: 0, length: count)
            self = regex.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: replaceWith)
        } catch { return }
    }

    var encoded: String? {
        return self.addingPercentEncoding(withAllowedCharacters: .controlCharacters)

    }
    func trim() -> String {
        return self.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
    }

    mutating func insert(string:String,ind:Int) {
        self.insert(contentsOf: string, at:self.index(self.startIndex, offsetBy: ind) )
    }


    var base64Decoded: String? {
        guard let decodedData = Data(base64Encoded: self) else { return nil }
        return String(data: decodedData, encoding: .utf8)
    }

    var base64Encoded: String? {
        let plainData = data(using: .utf8)
        return plainData?.base64EncodedString()
    }
}

@objc(Certificate)
class Certificate: NSObject {
    var publicKey:String? = nil
    var privateKey:String? = nil

    var keypair:MIHKeyPair? = nil
    var arrayKey:[UInt8]? = nil
    var aes: AES? = nil

    @objc(multiply:withB:withResolver:withRejecter:)
    func multiply(a: Float, b: Float, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        resolve(a*b)
    }

     @objc(generateKeys)
      func generateKeys() {
              SwiftRSACrypto.rsa_generate_key({ (keyPair, _) in
                  if let keyPair = keyPair {
                      if let pubKey = SwiftRSACrypto.getPublicKey(keyPair) {
                          publicKey = pubKey
                      }
                      print("\n")
                      if let priKey = SwiftRSACrypto.getPrivateKey(keyPair) {
                          privateKey = priKey
                      }
                      self.keypair = keyPair
                  }
              }, ofKeySize: .key2048, archiverFileName: nil)
      }

    @objc
    func getPublicKey(_ resolve: RCTPromiseResolveBlock, rejecter reject:RCTPromiseRejectBlock) -> Void {
        return resolve(publicKey!.trim())
    }

    @objc(decrypt:encryptedPublicKey:encryptedPrivateKey:subjectDN:sessionId:withResolver:withRejecter:)
    func decrypt(encryptedAesKey:String, encryptedPublicKey:String, encryptedPrivateKey:String, subjectDN:String, sessionId: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) {
        print("암호화된 AES 키: \(encryptedAesKey)")
        print("SubjectDN: \(subjectDN)")
        print("암호화된 공개키 HEX 정보: \(encryptedPublicKey)")
        print("암호화된 개인키 HEX 정보: \(encryptedPrivateKey)")

        guard let keypair = self.keypair else { return }


        let iv:[UInt8] = [123, 140, 56, 128, 22, 11,
                          170, 121, 33, 113, 73, 28,
                          208, 42, 247, 134]

        do {
            let aesBytes = Array<UInt8>(hex: encryptedAesKey)
            let data =  RSAUtil.decryptData(aesBytes.data, privateKey: self.privateKey!)!


            let aes = try! AES(key: data.bytes, blockMode: CBC(iv: iv), padding: .pkcs7)

            let decryptedPublicBytes = try! aes.decrypt(Array<UInt8>.init(hex: encryptedPublicKey))
            let decryptedPrivateBytes = try! aes.decrypt(Array<UInt8>.init(hex: encryptedPrivateKey))


            var issuedBy = ""

            let dnList = subjectDN.split(separator: ",")
            dnList.forEach { (str) in
                print("dn: \(str)")

                let dn = str.split(separator: "=")
                if dn[0] == "O" {
                    issuedBy = String(dn[1])
                    print("Issued By: \(issuedBy)")
                }
            }

            if (issuedBy == "") {
                return
            }

            let derData = String(bytes: decryptedPublicBytes, encoding: .utf8)
            let keyData = String(bytes: decryptedPrivateBytes, encoding: .utf8)

            resolve([derData, keyData, issuedBy])
        } catch {
            reject("decrypt", "decrypt", error)
        }
    }
    
    @objc(saveCertificate:fileData:withResolver:withRejecter:)
    func saveCertificate(filePath: String, fileData: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {

        var paths = filePath.components(separatedBy: "/")
        let filename = paths[paths.count-1].components(separatedBy: ".")
        paths.removeLast()

        let npkiURL = URL(fileURLWithPath: paths.joined(separator: "/"))
        let derURL = npkiURL.appendingPathComponent(filename[0]).appendingPathExtension(filename[1])
        
        do {
            let e1 = Array<UInt8>.init(hex: fileData)
            let derData = e1.data
            
            try! FileManager.default.createDirectory(atPath: npkiURL.path, withIntermediateDirectories: true, attributes: nil)
            try! derData.write(to: derURL)
            
            // let certFiles = try FileManager.default.contentsOfDirectory(atPath: npkiURL.path)
            resolve(["success", npkiURL.path])
        } catch {
            reject("saveCertificate", "saveCertificate", error)
        }
    }
    
    @objc(getCertificate:withResolver:withRejecter:)
    func getCertificate(filePath: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) {
        
        var paths = filePath.components(separatedBy: "/")
        let filename = paths[paths.count-1].components(separatedBy: ".")
        paths.removeLast()

        do {
            let npkiURL = URL(fileURLWithPath: paths.joined(separator: "/"))
            let derURL = npkiURL.appendingPathComponent(filename[0]).appendingPathExtension(filename[1])
            let data = try Data(contentsOf: derURL)
            
            let x509 = try X509Certificate(data: data)
            
            let subject = x509.subjectDistinguishedName ?? ""
            
            print(subject)
            let startDate = x509.notBefore
            let endDate = x509.notAfter
            var cn = ""
            subject.split(separator: ",").forEach { (x) in
                if x.contains("CN=") {
                    let str = String(x)
                    cn = str.trim().replacingOccurrences(of: "CN=", with: "")
                    
                    print("CN is \(cn)")
                    
                    cn.removingRegexMatches(pattern: "[A-Za-z0-9-]|[!&^%$*#@()/]")
                    
                    print(cn)
                    
                }
            }
            
            
            let dateStr = "\(startDate!.toFormat("yyyy.MM.dd")) - \(endDate!.toFormat("yyyy.MM.dd"))"
            
            resolve([filePath, cn, dateStr])
        } catch {
            reject("getCertificate", "getCertificate", error)
        }
    }
    
    @objc(getAesKey:publickKey:withResolver:withRejecter:)
    func getAesKey(key: String, publickKey: String, resolve: RCTPromiseResolveBlock, rejecter reject:RCTPromiseRejectBlock) -> Void {
        do {
            let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] as [UInt8]
            let arrayKey: [UInt8] = Array(key.utf8)
            self.arrayKey = arrayKey
            let aes = try! AES(key: arrayKey, blockMode: CBC(iv: iv), padding: .pkcs7)
            self.aes = aes
            let pKey = try PublicKey(base64Encoded: publickKey)
            let clear = try ClearMessage(data: arrayKey.data)
            let encrypted = try clear.encrypted(with: pKey, padding: .PKCS1)
            let data = encrypted.data
            let aesCipherKey = data.base64EncodedString()
            
            resolve(aesCipherKey)
        } catch {
            reject("getAesKey", "getAesKey", error)
        }
    }
    
    @objc(getEncryptedCert:withResolver:withRejecter:)
    func getEncryptedCert(path: String, resolve: RCTPromiseResolveBlock, rejecter reject:RCTPromiseRejectBlock) {
        do {
            var paths = path.components(separatedBy: "/")
            let filename = paths[paths.count-1].components(separatedBy: ".")
            paths.removeLast()
            let fileURL = URL(fileURLWithPath: paths.joined(separator: "/")).appendingPathComponent(filename[0]).appendingPathExtension(filename[1])
            
            let certData = try Data(contentsOf: fileURL)
        
            let certCipherBytes = try self.aes?.encrypt(certData.bytes)
            resolve(certCipherBytes?.toBase64())
        } catch {
            reject("getEncryptedCert", "getEncryptedCert", error)
        }
    }
    
    @objc(getEncryptedWithAES:withResolver:withRejecter:)
    func getEncryptedWithAES(str: String, resolve: RCTPromiseResolveBlock, rejecter reject:RCTPromiseRejectBlock) {
        let enc = try! self.aes?.encrypt(str.bytes)
        resolve(enc?.toBase64())
    }
}
