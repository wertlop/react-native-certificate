import { NativeModules } from 'react-native';

type CertificateType = {
  multiply(a: number, b: number): Promise<number>;
  decrypt(
    a: string,
    b: string,
    c: string,
    d: string,
    e: string
  ): Promise<object>;
  generateKeys(): void;
  getPublicKey(): Promise<string>;
  getCertificate(filepath: string): Promise<object>;
  saveCertificate(filepath: string, hexString: string): Promise<object>;
  getAesKey(key: string, publicKey: string): Promise<string>;
  getEncryptedCert(filepath: string): Promise<string>;
  getEncryptedWithAES(str: string): Promise<string>;
};

const { Certificate } = NativeModules;

export default Certificate as CertificateType;
