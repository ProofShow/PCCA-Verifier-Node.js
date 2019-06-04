'use strict';
const {describe, it} = require('mocha');
const {assert} = require('chai');
const fs = require('fs');
const PCCAVerifier = require('../index.js');

const PSES_DATA = {
  "gmail.com": {
    "DKIM Keys": [{
      "DNS Selector": "20161025",
      "Public Key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqRtqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB",
      "Not Before": "2019-05-01",
      "Not After": null
    }]
  }
};

describe('Certificate in PEM format', function() {

  it('should pass the verification', async function() {
    var result = null;
    var certBuffer = fs.readFileSync('./test/TEST_CERT_01.pem');
    var pccaVerifierObj = new PCCAVerifier(certBuffer, PSES_DATA);

    result = await pccaVerifierObj.verify();
    assert(result.retCode === 0, 'Failed to verify certificate');
  });
});
