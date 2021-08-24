# react-native-certificate

RSA by openssl and AES for certificate

## Installation

```sh
yarn add react-native-certificate
```

## Usage

```js
import Certificate from "react-native-certificate";

// ...

const result = await Certificate.decrypt();
const result = await Certificate.generateKeys();
const result = await Certificate.getPublicKey();
const result = await Certificate.getCertificate();
const result = await Certificate.saveCertificate();
const result = await Certificate.getAesKey();
const result = await Certificate.getEncryptedCert();
const result = await Certificate.getEncryptedWithAES();
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
