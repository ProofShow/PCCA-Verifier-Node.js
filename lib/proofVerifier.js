'use strict';
const asn1js = require("asn1js");
const pkijs = require('pkijs');
const simpleParser = require('./mailparser/simple-parser.js');
const dkim = require('./node-dkim/dkim.js');
const errors = require('./errors');

const MAIL_SUBJECT = 'Certificate Signing Request in accordance with PCCA Subscriber Agreement';
const MAIL_RECEIVER = 'csr@ca.proof.show';
const MAIL_CONTENTTYPE = 'text/plain';
const CERT_SUBJ_CN_OID = '2.5.4.3';
const CSR_PEM_BEGIN = '-----BEGIN CERTIFICATE REQUEST-----';
const CSR_PEM_END = '-----END CERTIFICATE REQUEST-----';

function ProofVerifier(certObj, rawMail, psesData) {
  this.certObj = certObj;
  this.rawMail = rawMail;
  this.psesData = psesData ? Object.assign({}, psesData) : null;

  /**
   * Start the verification procedure.
   * @return {number} The verificatioin result code.
   */
  this.verify = async function() {
    this.mailParser = await simpleParser(this.rawMail.replace(/\r?\n/g, '\r\n'));

    if (!this._testMailSubject())
      return errors.INVALID_MAIL_SUBJECT;
    else if (!this._testMailTo())
      return errors.INVALID_MAIL_TO;
    else if (!this._testMailFrom())
      return errors.INVALID_MAIL_FROM;
    else if (!this._testMailDate())
      return errors.INVALID_MAIL_DATE;
    else if (!this._testMailContentType())
      return errors.INVALID_MAIL_CONTENTTYPE;
    else if (!(await this._testMailBody()))
      return errors.INVALID_MAIL_BODY;
    else if (!(await this._testDKIMwithPSES()))
      return errors.INVALID_MAIL_DKIM;
    else
      return errors.SUCCESS;
  };

  /**
   *  Test email subject.
   *  @return {boolean} return true if pass the testing.
   */
  this._testMailSubject = function() {
    let subject = this.mailParser.subject.replace(/\s\s+/g, ' ');

    return (subject === MAIL_SUBJECT);
  };

  /**
   *  Test email "To" header.
   *  @return {boolean} return true if pass the testing.
   */
  this._testMailTo = function() {
    let mailTo = this.mailParser.to.value;

    return (mailTo.length === 1 && mailTo[0].address === MAIL_RECEIVER);
  };

  /**
   *  Test email "From" header.
   *  @return {boolean} return true if pass the testing.
   */
  this._testMailFrom = function() {
    let mailFrom = this.mailParser.from.value;
    let certCN = null;

    if (this.certObj.subject.typesAndValues.length === 1 && this.certObj.subject.typesAndValues[0].type === CERT_SUBJ_CN_OID)
      certCN = this.certObj.subject.typesAndValues[0].value.valueBlock.value;

    return (mailFrom.length === 1 && mailFrom[0].address === certCN);
  };

  /**
   *  Test email "Date" header.
   *  @return {boolean} return true if pass the testing.
   */
  this._testMailDate = function() {
    let certNotBeforeDate = new Date(this.certObj.notBefore.value);
    let mailSendDate = new Date(this.mailParser.date);

    return (certNotBeforeDate.getTime() === mailSendDate.getTime());
  };

  /**
   *  Test email "ContentType" header.
   *  @return {boolean} return true if pass the testing.
   */
  this._testMailContentType = function() {
    let contentType = null;

    if (this.mailParser.headers.has('content-type'))
      contentType = this.mailParser.headers.get('content-type').value;

    return (contentType === MAIL_CONTENTTYPE);
  };

  /**
   *  Test email body.
   *  @return {boolean} return true if pass the testing.
   */
  this._testCSRFormat = async function() {
    let emailBody = this.mailParser.text.trim();

    if (emailBody.startsWith(CSR_PEM_BEGIN) && emailBody.endsWith(CSR_PEM_END)) {
      let berCSR = emailBody.replace(CSR_PEM_BEGIN, '').replace(CSR_PEM_END, '').replace(/\r?\n/g, '');
      let csrBuffer = Buffer.from(berCSR, 'base64');
      let csrASN1 = asn1js.fromBER(csrBuffer.buffer.slice(csrBuffer.byteOffset, csrBuffer.byteOffset + csrBuffer.byteLength));

      this.csrObj = new pkijs.CertificationRequest({
        schema: csrASN1.result
      });
    }

    return (this.csrObj) ? await this.csrObj.verify() : false;
  };

  /**
   *  Test csr subject with certificate subject
   *  @return {boolean} return true if pass the testing.
   */
  this._testCSRSubject = function() {
    let csrSubjBuffer = Buffer.from(this.csrObj.subject.valueBeforeDecode);
    let certSubjBuffer = Buffer.from(this.certObj.subject.valueBeforeDecode);

    return (Buffer.compare(csrSubjBuffer, certSubjBuffer) === 0);
  };

  /**
   *  Test csr public key with certificate public key
   *  @return {boolean} return true if pass the testing.
   */
  this._testCSRPubkey = function() {
    let csrPubkeyModulusBuffer = Buffer.from(this.csrObj.subjectPublicKeyInfo.parsedKey.modulus.valueBlock.valueHex);
    let csrPubkeyExponent = this.csrObj.subjectPublicKeyInfo.parsedKey.publicExponent.valueBlock.valueDec;
    let certPubkeyModulusBuffer = Buffer.from(this.certObj.subjectPublicKeyInfo.parsedKey.modulus.valueBlock.valueHex);
    let csrtPubkeyExponent = this.certObj.subjectPublicKeyInfo.parsedKey.publicExponent.valueBlock.valueDec;

    return (Buffer.compare(csrPubkeyModulusBuffer, certPubkeyModulusBuffer) === 0 && csrPubkeyExponent === csrtPubkeyExponent);
  };

  /**
   *  Test email body.
   *  @return {boolean} return true if pass the testing.
   */
  this._testMailBody = async function() {
    if (!(await this._testCSRFormat()))
      return false;
    else if (!this._testCSRSubject())
      return false;
    else if (!this._testCSRPubkey())
      return false;

    return true;
  };

  /**
   *  Test mail DKIM signature with PSES
   *  @return {boolean} return true if pass the testing.
   */
  this._testDKIMwithPSES = async function() {
    if (this.psesData) {
      let self = this;
      let rawMailBuffer = Buffer.from(self.rawMail);
      let dkimRetrieverDone = false;
      let dkimKeyRetrieverFn = function(domain, selector, callback) {
        let dkimRecord = null;

        if (self.psesData[domain] && self.psesData[domain]['DKIM Keys'].length > 0) {
          while (self.psesData[domain]['DKIM Keys'].length > 0) {
            let tmpDKIMRecord = self.psesData[domain]['DKIM Keys'].shift();
            let mailSendDate = new Date(self.mailParser.date);
            let tmpDKIMRecordStartDate = new Date(Date.parse(tmpDKIMRecord['Not Before']));
            let tmpDKIMRecordEndDate = (tmpDKIMRecord['Not After']) ? new Date(Date.parse(tmpDKIMRecord['Not After'])) : null;

            if (tmpDKIMRecordEndDate)
              tmpDKIMRecordEndDate.setUTCHours(23, 59, 59, 999);

            if (tmpDKIMRecord['DNS Selector'] === selector) {
              if (mailSendDate.getTime() >= tmpDKIMRecordStartDate.getTime()) {
                if (tmpDKIMRecordEndDate === null || mailSendDate.getTime() <= tmpDKIMRecordEndDate.getTime()) {
                  dkimRecord = tmpDKIMRecord;
                  break;
                }
              }
            }
          }

          if (dkimRecord)
            callback(null, Buffer.from(dkimRecord['Public Key'], 'base64'));
          else
            callback('failed to find DKIM record', null);
        } else {
          dkimRetrieverDone = true;
          callback('failed to find DKIM record', null);
        }
      };
      let dkimVerifyFn = async function() {
        return new Promise(function(resolve, reject) {
          dkim.verify(rawMailBuffer, dkimKeyRetrieverFn, function(err, res) {
            if (err)
              resolve(null);
            else
              resolve(res);
          });
        });
      };
      let isAllPass = false;

      while (!isAllPass && !dkimRetrieverDone) {
        let dkimRes = await dkimVerifyFn();

        if (dkimRes) {
          isAllPass = dkimRes.every(function(dkimInfo) {
            return (dkimInfo.verified === true) ? true : false;
          });
        }
      }

      return isAllPass;
    } else
      return false;
  };
}

module.exports.ProofVerifier = ProofVerifier;
