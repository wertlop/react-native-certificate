import { NativeModules } from 'react-native';

type CertificateType = {
  multiply(a: number, b: number): Promise<number>;
};

const { Certificate } = NativeModules;

export default Certificate as CertificateType;
