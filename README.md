# Certificate API
This is a simple API deployed in Go which provides information serialized in JSON data about x509 certificates. It can also
fetch x509 certificates from TLS-enabled sites and parse them.
Feel free to use the public endpoint available at https://certapi.mracs.dev/

## Installation
Run `make` to build the binary. It'll be installed in `build/certificateapi`. Simply run this executable.
### Environment Variables
By default, the application listens on port `8080`. You can change this by setting the `PORT` environment variable to what you want.
When running in production, set this environment variable: `GIN_MODE=release`

## How to Query Information for Websites
Send a GET request to `https://certapi.mracs.dev/` with the query parameter `q` set to equal the site you wish to dial.
Ex: `https://certapi.mracs.dev/?q=www.google.com`

### Response & Types
#### Error
If the status !== `true`, there will be a message field which displays the error.
```ts
{
  status: false,
  message: string,
}
```

### 200 | SUCCESS
```ts
{
  status: true | false,
  subject: {
    commonName: string,
    organization: string[],
    organizationalUnit: string[],
    locality: string[],
    country: string[],
  },
  issuer: {
    commonName: string,
    organization: string[],
    organizationalUnit: string[],
    locality: string[],
    country: string[],
  },
  validationType: 'DV' | 'OV' | 'EV',
  signatureAlgorithm: string,
  publicKeyAlgorithm: string,
  serialNumber: number,
  notAfter: Date,
  /**
    - 0: KeyUsageCRLSign
    - 1: KeyUsageCertificateSign
    - 2: KeyUsageContentCommitment
    - 3: KeyUsageDataEncipherment
    - 4: KeyUsageDecipherOnly
    - 5: KeyUsageDigitalSignature
    - 6: KeyUsageEncipherOnly
    - 7: KeyUsageKeyAgreement
    - 8: KeyUsageKeyEncipherment
  */
  keyUsage: number[],
  keyUsageAsText: ['CRL Signing', 'Certificate Signing', 'Content Commitment', 'Data Encipherment', 'Decipher Only', 'Digital Signature', 'Encipher Only', 'Key Agreement', 'Key Encipherment'],
  /**
    - 0: Any/All Usage
    - 1: TLS Web Server Auth
    - 2: TLS Web Client Auth
    - 3: Code Signing
    - 4: Email Protection (S/MIME)
  */
  extendedKeyUsage: number[],
  extendedKeyUsageAsText: ['All/Any Usages', 'TLS Web Server Authentication', 'TLS Web Client Authentication', 'Code Signing', 'E-mail Protection (S/MIME)'],
  san: string,
  fingerprint: string,
  connection: {
    cipherSuite: string,
    tlsVersion: 'SSLv3' | 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3',
  },
}
```

## How to Parse PEM-Encoded X509 certificate data
Submit a POST request to https://certapi.mracs.dev/parse with the body being the raw/text content of the PEM encoded certificate.

### Response & Types
#### Error
If the status !== `true`, there will be a message field which displays the error.
```ts
{
  status: false,
  message: string,
}
```

### 200 | SUCCESS
```ts
{
  status: true | false,
  subject: {
    commonName: string,
    organization: string[],
    organizationalUnit: string[],
    locality: string[],
    country: string[],
  },
  issuer: {
    commonName: string,
    organization: string[],
    organizationalUnit: string[],
    locality: string[],
    country: string[],
  },
  aia: {
    issuingCertificateURL: string,
    ocspServer: string,
  },
  validationType: 'DV' | 'OV' | 'EV',
  signatureAlgorithm: string,
  publicKeyAlgorithm: string,
  serialNumber: number,
  notAfter: Date,
  /**
    - 0: KeyUsageCRLSign
    - 1: KeyUsageCertificateSign
    - 2: KeyUsageContentCommitment
    - 3: KeyUsageDataEncipherment
    - 4: KeyUsageDecipherOnly
    - 5: KeyUsageDigitalSignature
    - 6: KeyUsageEncipherOnly
    - 7: KeyUsageKeyAgreement
    - 8: KeyUsageKeyEncipherment
  */
  keyUsage: number[],
  keyUsageAsText: ['CRL Signing', 'Certificate Signing', 'Content Commitment', 'Data Encipherment', 'Decipher Only', 'Digital Signature', 'Encipher Only', 'Key Agreement', 'Key Encipherment'],
  /**
    - 0: Any/All Usage
    - 1: TLS Web Server Auth
    - 2: TLS Web Client Auth
    - 3: Code Signing
    - 4: Email Protection (S/MIME)
  */
  extendedKeyUsage: number[],
  extendedKeyUsageAsText: ['All/Any Usages', 'TLS Web Server Authentication', 'TLS Web Client Authentication', 'Code Signing', 'E-mail Protection (S/MIME)'],
  san: string,
  emailAddresses: string,
  fingerprint: string,
}
```
