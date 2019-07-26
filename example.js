'use strict';
const fs = require('fs');
const fetch = require('node-fetch');
const PCCAVerifier = require('./index.js');
const pckageJson = require('./package.json');

const PSES_DOWNLOAD_URL = 'https://download.ca.proof.show/PSES.json';
const ERROR_MESSAGE = "The input certificate does not carry a valid DKIM proof of CSR";
const RESULT_MESSAGE = [
  'The input certificate is correctly formatted and carries a valid DKIM proof of CSR.',
  'The input certificate is not correctly formatted.',
  ERROR_MESSAGE + ' (Invalid mail \"subject\")',
  ERROR_MESSAGE + ' (Invalid mail \"to\")',
  ERROR_MESSAGE + ' (Invalid mail \"from\")',
  ERROR_MESSAGE + ' (Invalid mail \"date\")',
  ERROR_MESSAGE + ' (Invalid mail \"content-type\")',
  ERROR_MESSAGE + ' (Invalid mail body)',
  ERROR_MESSAGE + ' (Invalid mail DKIM signature)'
];

/**
 *  Retrieve PSES from remote.
 */
async function retrievePSES() {
  try {
    var psesData = null;
    var fetchRes = await fetch(PSES_DOWNLOAD_URL);

    if (fetchRes.ok)
      return await fetchRes.json();
    else
      throw fetchRes.statusText;
  } catch (err) {
    return null;
  }
}

/**
 * Main process of PCCA Verifier program
 */
async function main() {
  var certPath = process.argv[2];

  // check argument
  if (certPath) {
    var result = null;
    var psesData = await retrievePSES();
    var certBuffer = fs.readFileSync(certPath);
    var pccaVerifierObj = new PCCAVerifier(certBuffer, psesData);

    result = await pccaVerifierObj.verify();

    console.log(`PCCAVerifier Version ${pckageJson.version} - ProofShow Inc.`);
    console.log('');
    console.log('  ' + RESULT_MESSAGE[result.retCode]);

    if (result.retCode === 0) {
      console.log('');
      console.log('  Certificate Subject:    ' + result.subject);
      console.log('  Certificate Key Hash:   ' + result.keyHash);
      console.log('  Certificate Not Before: ' + result.notBefore);
      console.log('  Certificate Not After:  ' + result.notAfter);
      console.log('');
    }

    process.exit(0);
  } else {
    console.log('Invalid argument');
    process.exit(1);
  }
}

// execute main process
main();
