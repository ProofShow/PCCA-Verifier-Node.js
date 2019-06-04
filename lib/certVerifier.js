'use strict';
const asn1js = require("asn1js");
const pkijs = require('pkijs');
const {Crypto} = require("@peculiar/webcrypto");
const util = require('./util');
const errors = require('./errors');
const ProofVerifier = require('./proofVerifier').ProofVerifier;

const PCCA_VERIFIER_VER = '0.99.53119';
const CERT_PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const CERT_PEM_END = '-----END CERTIFICATE-----';
const CERT_BASICCONSTRAINTS_OID = '2.5.29.19';
const CERT_KEYUSAGE_OID = '2.5.29.15';
const CERT_POLICY_OID = '2.5.29.32';
const CERT_AIA_OID = '1.3.6.1.5.5.7.1.1';
const CERT_CRL_DIST_OID = '2.5.29.31';
const PROOF_EMAIL_OID = '1.3.6.1.4.1.51803.2.1';
const CERT_POLICY_DATA = 'MIHcMIHZBgorBgEEAYOUWwECMIHKMCUGCCsGAQUFBwIBFhlodHRwczovL2Nwcy5jYS5wcm9vZi5zaG93MIGgBggrBgEFBQcCAjCBkxqBkFRoaXMgQ2VydGlmaWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQYXJ0aWVzIGFuZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vY3AuY2EucHJvb2Yuc2hvdw==';
const CERT_AIA_DATA = 'MEQwQgYIKwYBBQUHMAKGNmh0dHBzOi8vZG93bmxvYWQuY2EucHJvb2Yuc2hvdy9pc3N1ZXIvaW50ZXJtZWRpYXRlLnBlbQ==';
const CERT_CRL_DIST_DATA = 'MCkwJ6AloCOGIWh0dHBzOi8vY3JsLmNhLnByb29mLnNob3cvdjEvZmlsZQ==';
const CERT_ROOT_BER = 'MIIFYjCCA0qgAwIBAgIJAJfz/bGuUowiMA0GCSqGSIb3DQEBCwUAMD4xCzAJBgNVBAYTAlRXMRcwFQYDVQQKDA5Qcm9vZlNob3cgSW5jLjEWMBQGA1UEAwwNUENDQSBSb290IENBMTAeFw0xOTA1MDIwMjI3NTZaFw00NDA1MDEwMjI3NTZaMD4xCzAJBgNVBAYTAlRXMRcwFQYDVQQKDA5Qcm9vZlNob3cgSW5jLjEWMBQGA1UEAwwNUENDQSBSb290IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALRhOdG7k/2Nb6c6MAo8aCqLoKAKGdsTUbvstKQRvOnTLGJ8w7BA+9v7GNxM5+f/Zto6T8ygYbLnVHBvSRPdYLwm0rbD1/XdWsNkMHIJgQ8V25+PHOKiFKUNL0TJoSbtvfhYcAaKNwmSCRd3a9aKZluPnGTvP2mxNLbRuS0KvNmSNs4gHaqfJsqD/aTxyC0vBoLOYhSY5sDv5Wck1Xow/PjTJLDfcB0nMqxlkJ3M3Fn4MNVtAZdu4UKOhOPh8bJp70lQ8efHjD9uIz3xFnxj6CrMnSJsldq8Dsap8omhot2kQp28fZRwSZJbAxt4cUqtrgwOvk2p94aTlX0K5OT8QKpSyumsh+g8HqhSQJX3CcoSA6XPwfCVtyukZ9sNm3L0PbbMjwy4g2shcSgfIgxGsucdWk+lkvKQfYFjQ0aaqKDfXvlHpa2K8NttE8qW5e4UwPlZp+MF/EVe+WuzxnzinXKWfV5dlEY1sxVn8Hwga172bnSkdweRCYkEPVmAKAGuTm5tLueibSthzy0jIzdLcM55+6xV6NAeSLN7C+ZW457GY58hoyriskFN+E4FBAHrxwE8HlAtqDupQobiSGCOCcJzlZoJ4pjuIAr391YU7oVDLSOlPX4cgsHQF1S7z0dzwvaDsJUSSTUPPPTPa6XzQvg1IfX2sO2pjPgiDGD1Lo1rAgMBAAGjYzBhMB0GA1UdDgQWBBQWhHFv1rAqd30owDDPNzncSGHRMTAfBgNVHSMEGDAWgBQWhHFv1rAqd30owDDPNzncSGHRMTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEARqoNHY4HYlTi9VOLKhwNuCWNq8dFb5XX4DTwmgKk+MFqvQ7ht3KzTeZm16rXU35juQYYEvq9WZK3HuMvaHJaH0BE424bDppXrSNcBSbjSUagOlwO0rM+yApn8AhGCZkQOqJiCbWQD+n+KBevZaxY1NaaC/qHybMVb9buzqNy3Hb3Nu0jGewqmUSLwo4off4PQ7MvgBNFZZBjzWu1tf3ZYOUXRDHbT3Bw9B6z/3FEoFmAXot/s27U8d5Vv3atpBV7FouUdcP+6O5rQiyTzZZhgRzZqsOgWkHe4qjAG8Nmi3C+lzINlQzKpwKgKQm/M0bmOu6XNrhCdpABNGn+f6sva6GKI/wkDsN6wlp6plPlg/EQWiCmOtYvuFvMox3lHVaT/+edbnjqPpEz+IRr/8hTdJKc8hDdEg5rZlF6uCAasPubteBpjosBSgXb0iog+fB9R4BWbw4pCceJq5SvqRCEK0lN42tckHnUEvnIa6hfyMjarqBYc9gU9woyGs3Prh6OM1TV7zh9HTX4RT36yX2zEjOsUqpIkN2JXPoB5kaO82BQFRAGMbL4rmG8iXXKkoJdXhVB3k91nnNCENlDdL36oK6OSaXZ7dJyp55wBr2rj18YqnbA+Q5tpa+yO/cGcISGMzGe54xWy1ByVZQUsnUKjMiJ3oFKksdnCgEBXIOcAXo=';
const CERT_INTERMEDIATE_BER = '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';
const ASN1_SKIP_OFFSET_4 = 4;
const CERT_VALIDITY_PERIOD_SEC = 60;

function CertVerifier(certBuffer, psesData) {

  this.certBuffer = certBuffer;
  this.psesData = psesData;

  // set crypto engine for pki.js
  let webcrypto = new Crypto();
  pkijs.setEngine("newEngine", webcrypto, new pkijs.CryptoEngine({
    name: "",
    crypto: webcrypto,
    subtle: webcrypto.subtle
  }));

  // parse certificate with pki.js
  try {
    let certStr = this.certBuffer.toString();
    let certDerB64 = null;
    let certASN1 = null;

    // parse in PEM or DER format
    if (certStr.startsWith(CERT_PEM_BEGIN)) {
      certDerB64 = certStr.replace(CERT_PEM_BEGIN, '').replace(CERT_PEM_END, '').replace(/\r?\n/g, '');
      certASN1 = asn1js.fromBER(util.toArrayBuffer(Buffer.from(certDerB64, 'base64')));
    } else {
      certASN1 = asn1js.fromBER(util.toArrayBuffer(this.certBuffer));
    }

    this.certificate = new pkijs.Certificate({
      schema: certASN1.result
    });
  } catch(err) {
    console.log(err);
    throw 'Failed to parse certificate';
  }

  /**
   * Start the verification procedure.
   * @return {Object} The reply object.
   */
  this.verify = async function() {
    var result = errors.UNKNOWN;
    var response = {};

    this.emailProof = '';

    if (!(await this._testCertFormat()))
      result = errors.INVALID_CERT_FORMAT;
    else
      result = await this._exeProofVerifier();

    response.retCode = result;
    response.subject = this._extractCertCN();
    response.keyHash = this._extractSubjectKeyID();
    response.notBefore = this._formatDateStr(new Date(this.certificate.notBefore.value));
    response.notAfter = this._formatDateStr(new Date(this.certificate.notAfter.value));

    return response;
  };

  /**
   *  Extract X509 extension by OID.
   *  @param {string} oid The OID of extension
   *  @return {Object} the extnesin object
   */
  this._extractExtension = function(oid) {
    let extension = null;

    for (let extIdx = 0; extIdx < this.certificate.extensions.length; extIdx++) {
      if (this.certificate.extensions[extIdx].extnID === oid) {
        extension = this.certificate.extensions[extIdx];
        break;
      }
    }

    return extension;
  };

  /**
   *  Test certificate serial number.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertSN = function() {
    let serialNumHex = Buffer.from(this.certificate.serialNumber.valueBlock.valueHex).toString('hex');

    if (serialNumHex.length === 40)
      return true;
    else {
      serialNumHex = serialNumHex.replace(/^0+/, '');
      return (serialNumHex.length === 40);
    }
  };

  /**
   *  Test certificate issuer.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertIssuer = async function() {
    let intermediateASN1 = asn1js.fromBER(util.toArrayBuffer(Buffer.from(CERT_INTERMEDIATE_BER, 'base64')));
    let intermediateCert = new pkijs.Certificate({
      schema: intermediateASN1.result
    });
    let rootASN1 = asn1js.fromBER(util.toArrayBuffer(Buffer.from(CERT_ROOT_BER, 'base64')));
    let rootCert = new pkijs.Certificate({
      schema: rootASN1.result
    });
    let certNotBeforeVerificationEngine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: [rootCert],
      certs: [intermediateCert, this.certificate],
      checkDate: new Date(this.certificate.notBefore.value)
    });
    let certNotAfterVerificationEngine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: [rootCert],
      certs: [intermediateCert, this.certificate],
      checkDate: new Date(this.certificate.notAfter.value)
    });
    let notBeforeVerifyRes = await certNotBeforeVerificationEngine.verify();
    let notAfterVerifyRes = await certNotAfterVerificationEngine.verify();

    return (notBeforeVerifyRes.result && notAfterVerifyRes.result);
  };

  /**
   *  Test certificate validity period.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertValidityPeriod = function() {
    let notBeforeDate = new Date(this.certificate.notBefore.value);
    let notAfterDate = new Date(this.certificate.notAfter.value);

    return ((notAfterDate.getTime() - notBeforeDate.getTime()) === (CERT_VALIDITY_PERIOD_SEC * 1000));
  };

  /**
   *  Test certificate BasicConstraints extension.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertBasicConstraints = function() {
    let isCriticalPass = false;
    let isValuePass = false;
    let extension = this._extractExtension(CERT_BASICCONSTRAINTS_OID);

    if (extension) {
      isCriticalPass = (extension.critical === false);

      if (Object.keys(extension.parsedValue).length === 1)
        isValuePass = (extension.parsedValue.cA === false);
    }

    return (isCriticalPass && isValuePass);
  };

  /**
   *  Test certificate KeyUsave extension.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertKeyUsage = function() {
    let isCriticalPass = false;
    let isValuePass = false;
    let extension = this._extractExtension(CERT_KEYUSAGE_OID);

    if (extension) {
      isCriticalPass = (extension.critical === true);

      // key usage bits: 11000000
      isValuePass = (Buffer.from(extension.parsedValue.valueBlock.valueHex).toString('hex') === 'c0');
    }

    return (isCriticalPass && isValuePass);
  };

  /**
   *  Test certificate Policy extension.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertPolicy = function() {
    let isCriticalPass = false;
    let isValuePass = false;
    let extension = this._extractExtension(CERT_POLICY_OID);

    if (extension) {
      isCriticalPass = (extension.critical === false);

      // check policy with constant binary data
      isValuePass = (Buffer.from(extension.extnValue.valueBlock.valueHex).toString('base64') === CERT_POLICY_DATA);
    }

    return (isCriticalPass && isValuePass);
  };

  /**
   *  Test certificate AIA extension.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertAIA = function() {
    let isCriticalPass = false;
    let isValuePass = false;
    let extension = this._extractExtension(CERT_AIA_OID);

    if (extension) {
      isCriticalPass = (extension.critical === false);

      // check AIA with constant binary data
      isValuePass = (Buffer.from(extension.extnValue.valueBlock.valueHex).toString('base64') === CERT_AIA_DATA);
    }

    return (isCriticalPass && isValuePass);
  };

  /**
   *  Test certificate CRLDistributionPoints extension.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertCRLDist = function() {
    let isCriticalPass = false;
    let isValuePass = false;
    let extension = this._extractExtension(CERT_CRL_DIST_OID);

    if (extension) {
      isCriticalPass = (extension.critical === false);

      // check AIA with constant binary data
      isValuePass = (Buffer.from(extension.extnValue.valueBlock.valueHex).toString('base64') === CERT_CRL_DIST_DATA);
    }

    return (isCriticalPass && isValuePass);
  };

  /**
   *  Test certificate key length.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertKeyLen = function() {
    // key length is 2048 bits
    return (this.certificate.subjectPublicKeyInfo.parsedKey.modulus.valueBlock.valueHex.byteLength === 256);
  };

  /**
   *  Test existence of certificate proof
   *  @return {boolean} return true if pass the testing.
   */
  this._testEmailProof = function() {
    let isCriticalPass = false;
    let extension = this._extractExtension(PROOF_EMAIL_OID);

    if (extension) {
      isCriticalPass = (extension.critical === false);

      this.emailProof = Buffer.from(extension.extnValue.valueBlock.valueHex).slice(ASN1_SKIP_OFFSET_4).toString();
    }

    return (isCriticalPass && this.emailProof.length > 0);
  };

  /**
   *  Test certificate format
   *  @return {boolean} return true if pass the testing.
   */
  this._testCertFormat = async function() {
    try {
      if (!this._testCertSN())
        return false;
      else if (!(await this._testCertIssuer()))
        return false;
      else if (!this._testCertValidityPeriod())
        return false;
      else if (!this._testCertBasicConstraints())
        return false;
      else if (!this._testCertKeyUsage())
        return false;
      else if (!this._testCertPolicy())
        return false;
      else if (!this._testCertAIA())
        return false;
      else if (!this._testCertCRLDist())
        return false;
      else if (!this._testCertKeyLen())
        return false;
      else if (!this._testEmailProof())
        return false;

      return true;
    } catch (err) {
      console.log(err);
      return false;
    }
  };

  /**
   *  Test certificate proof with ProofVerifier
   *  @return {number} The verification result code
   */
  this._exeProofVerifier = async function() {
    var proofVerifierObj = null;

    proofVerifierObj = new ProofVerifier(this.certificate, Buffer.from(this.emailProof, 'base64').toString(), this.psesData);

    return await proofVerifierObj.verify();
  };

  /**
   *  Extract common name from certificate.
   *  @return {string} The common name of certificate.
   */
  this._extractCertCN = function() {
    var certCN = '';

    this.certificate.subject.typesAndValues.forEach(function(typeAndValue) {
      if (certCN.length === 0 && typeAndValue.type === '2.5.4.3') {
        certCN = typeAndValue.value.valueBlock.value;
      }
    });

    return certCN;
  };

  /**
   *  Extract subject key ID from certificate.
   *  @return {string} The hex string of subject key ID.
   */
  this._extractSubjectKeyID = function() {
    var subjectKeyID = '';

    for(let extIdx = 0; extIdx < this.certificate.extensions.length; extIdx++) {
      if (this.certificate.extensions[extIdx].extnID === '2.5.29.14') {
        for (let byte of Buffer.from(this.certificate.extensions[extIdx].parsedValue.valueBlock.valueHex)) {
          if (subjectKeyID.length !== 0)
            subjectKeyID += ':';

          subjectKeyID += byte.toString(16).toUpperCase().padStart(2, '0');
        }
        break;
      }
    }

    return subjectKeyID;
  };

  /**
   *  Format the date object to string.
   *  @param {Object} date The date object.
   *  @return {string} The formatted date string.
   */
  this._formatDateStr = function(date) {
    var dateYear = date.getFullYear();
    var dateMonth = (date.getMonth() + 1).toString().padStart(2, '0');
    var dateDate = date.getDate().toString().padStart(2, '0');
    var dateHour = date.getHours().toString().padStart(2, '0');
    var dateMinutes = date.getMinutes().toString().padStart(2, '0');
    var dateSeconds = date.getSeconds().toString().padStart(2, '0');

    return `${dateYear}/${dateMonth}/${dateDate} ${dateHour}:${dateMinutes}:${dateSeconds}`;
  };
}

module.exports.CertVerifier = CertVerifier;
