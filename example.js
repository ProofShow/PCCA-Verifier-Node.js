'use strict';
const fs = require('fs');
const fetch = require('node-fetch');
const PCCAVerifier = require('./index.js');
const pckageJson = require('./package.json');

const PSES_DOWNLOAD_URL = 'https://download.ca.proof.show/PSES.json';
const RESULT_MESSAGE = [
  'Successfully verify PCCA certificate.',
  'Invalid certificate format.',
  'Invalid mail \"subject\".',
  'Invalid mail \"to\".',
  'Invalid mail \"from\".',
  'Invalid mail \"date\".',
  'Invalid mail \"content-type\".',
  'Invalid mail body.',
  'Invalid mail DKIM signature.'
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
