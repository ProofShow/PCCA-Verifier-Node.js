## PCCA Verifier
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![npm version](https://badge.fury.io/js/pcca-verifier.svg)](https://badge.fury.io/js/pcca-verifier)
[![Known Vulnerabilities](https://snyk.io/test/github/ProofShow/PCCAVerifier/badge.svg?targetFile=package.json)](https://snyk.io/test/github/ProofShow/PCCAVerifier?targetFile=package.json)

PCCA Verifier is a Node.js library for verifying Proof-Carrying Certificates™ issued by [PCCA](https://pcca.proof.show). The verification is done by

- Checking if the input certificate is correctly formatted according to [PCCA Certification Practice Statement](https://www.proof.show/pcca/PCCA_CPS.pdf);
- Checking if the input certificate, in particular, carries a DKIM Proof of CSR;
- Checking if the DKIM Proof of CSR can support the issuance of the input certificate according to the tracked DKIM keys of [PCCA Supported Email Services (PSES)](https://www.proof.show/pcca.html#pses).

### Requirement
- Node.js v10.x.x

### How to install
To install this library, run the following:

```
npm install --save pcca-verifier
```

### How to use
To use this library, study the sample code in `example.js` which can be run by the following:

```
node example.js PATH_OF_CERT
```

### License
AGPL-3.0-or-later
