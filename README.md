## PCCA Verifier
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

PCCA Verifier can be used to verify a PCCA certificate by checking

- If the certificate is correctly formatted according to [PCCA Certification Practice Statement](https://www.proof.show/pcca/PCCA_CPS.pdf);
- If the certificate, in particular, carries a DKIM Proof of CSR;
- If the DKIM Proof of CSR, along with the corresponding DKIM key at the time when the certificate was issued, can support the issuance of the certificate.

### Requirement
- Node.js 8.9.4 or higher

### How to install
To install the library, run the following:

```
npm install --save pcca-verifier
```

### How to use
Check example code in `example.js` or run the following:

```
node example.js PATH_OF_CERT
```

### License
AGPL-3.0-or-later
