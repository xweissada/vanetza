#include <vanetza/common/its_aid.hpp>

#include <vanetza/security/persistence.hpp>

#include <vanetza/asn1/pki/EtsiTs103097Certificate.h>
#include <vanetza/asn1/pki/EnrolmentRequestMessage.h>
#include <vanetza/asn1/pki/AuthorizationRequestMessageWithPop.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>

#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/sha.hpp>

#include <cryptopp/oids.h>
#include <cryptopp/files.h>

#include <cpr/cpr.h>

#include "helpers.h"
#include "enrolment.h"

using namespace vanetza::security;

void CertificateManager::ConstructInnerEcRequest(InnerEcRequest& innerEc)
{
  OCTET_STRING_fromBuf(&innerEc.itsId, itssId.data(), itssId.size());

  innerEc.certificateFormat = CertificateFormat_ts103097v131;
  innerEc.publicKeys.encryptionKey = nullptr;

  innerEc.publicKeys.verificationKey.present = PublicVerificationKey_PR_ecdsaNistP256;
  ecdsa256::PublicKey verificationPubKey = verificationKeyPair.public_key;
  if (verificationPubKey.y.back() % 2) {
    innerEc.publicKeys.verificationKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR_compressed_y_1;
    OCTET_STRING& verKey = innerEc.publicKeys.verificationKey.choice.ecdsaNistP256.choice.compressed_y_1;
    OCTET_STRING_fromBuf(&verKey, (char *)verificationPubKey.x.data(), verificationPubKey.x.size());
  }
  else {
    innerEc.publicKeys.verificationKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR_compressed_y_0;
    OCTET_STRING& verKey = innerEc.publicKeys.verificationKey.choice.ecdsaNistP256.choice.compressed_y_0;
    OCTET_STRING_fromBuf(&verKey, (char *)verificationPubKey.x.data(), verificationPubKey.x.size());  
  }

  innerEc.requestedSubjectAttributes.appPermissions = vanetza::asn1::allocate<SequenceOfPsidSsp>();
  PsidSsp* signPermission = vanetza::asn1::allocate<PsidSsp>();
  signPermission->psid = vanetza::aid::SCR;
  signPermission->ssp = vanetza::asn1::allocate<ServiceSpecificPermissions>();
  signPermission->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
  std::array<uint8_t, 2> signSspBitmap = {0x01, 0xC0};
  OCTET_STRING_fromBuf(&signPermission->ssp->choice.bitmapSsp, (char *)signSspBitmap.data(), signSspBitmap.size());
  ASN_SEQUENCE_ADD(innerEc.requestedSubjectAttributes.appPermissions, signPermission);

  uint8_t assuranceLevel[1] = {0xE0};
  innerEc.requestedSubjectAttributes.assuranceLevel = vanetza::asn1::allocate<SubjectAssurance_t>();
  OCTET_STRING_fromBuf(innerEc.requestedSubjectAttributes.assuranceLevel, (char *)assuranceLevel, 1);

  std::string itsEcId = itssId + std::to_string(ecGenerationTime);
  innerEc.requestedSubjectAttributes.id = vanetza::asn1::allocate<CertificateId>();
  innerEc.requestedSubjectAttributes.id->present = CertificateId_PR_name;
  OCTET_STRING_fromBuf(&innerEc.requestedSubjectAttributes.id->choice.name, itsEcId.data(), itsEcId.size());

  innerEc.requestedSubjectAttributes.certIssuePermissions = nullptr; // not included
  innerEc.requestedSubjectAttributes.region = nullptr; // optional
  innerEc.requestedSubjectAttributes.validityPeriod = nullptr; // optional
}

void CertificateManager::ConstructToBeSignedData(ToBeSignedData& tbsData, const vanetza::ByteBuffer& payload)
{
  tbsData.payload = vanetza::asn1::allocate<SignedDataPayload>();
  tbsData.payload->data = vanetza::asn1::allocate<Ieee1609Dot2Data>();
  tbsData.payload->data->protocolVersion = 3L;
  tbsData.payload->data->content = vanetza::asn1::allocate<Ieee1609Dot2Content>();
  tbsData.payload->data->content->present = Ieee1609Dot2Content_PR_unsecuredData;
  OCTET_STRING& unsecuredData = tbsData.payload->data->content->choice.unsecuredData;
  OCTET_STRING_fromBuf(&unsecuredData, (char *)payload.data(), payload.size());
  tbsData.payload->extDataHash = nullptr;

  tbsData.headerInfo.psid = vanetza::aid::SCR;

  tbsData.headerInfo.generationTime = vanetza::asn1::allocate<Time64_t>();
  asn_uint642INTEGER(tbsData.headerInfo.generationTime, ecGenerationTime);

  tbsData.headerInfo.encryptionKey = nullptr;
  tbsData.headerInfo.expiryTime = nullptr;
  tbsData.headerInfo.generationLocation = nullptr;
  tbsData.headerInfo.inlineP2pcdRequest = nullptr;
  tbsData.headerInfo.missingCrlIdentifier = nullptr;
  tbsData.headerInfo.p2pcdLearningRequest = nullptr;
  tbsData.headerInfo.requestedCertificate = nullptr;
}

void CertificateManager::ConstructEtsiTs102941Data(EtsiTs102941Data& data102941, EtsiTs102941DataContent_PR contentType)
{
  data102941.version = Version_v1;

  if (contentType == EtsiTs102941DataContent_PR_enrolmentRequest) {
    // Generate ephemeral keypair.
    verificationKeyPair = backend.generate_key_pair();

    // Construct inner EC request.
    vanetza::asn1::asn1c_oer_wrapper<InnerEcRequest> innerEc { asn_DEF_InnerEcRequest };
    ConstructInnerEcRequest(*innerEc);
    vanetza::ByteBuffer innerEcBuf = innerEc.encode();

    // Construct InnerEcRequestSignedForPOP
    data102941.content.present = EtsiTs102941DataContent_PR_enrolmentRequest;
    InnerEcRequestSignedForPop_t& innerEcSigned = data102941.content.choice.enrolmentRequest;
    ConstructSelfSignedData(innerEcSigned, verificationKeyPair.private_key, innerEcBuf);
  }
  else if (contentType == EtsiTs102941DataContent_PR_authorizationRequest) {
    data102941.content.present = EtsiTs102941DataContent_PR_authorizationRequest;
    InnerAtRequest& innerAtRequest = data102941.content.choice.authorizationRequest;
    ConstructInnerAtRequest(innerAtRequest);
  }
}

void CertificateManager::ConstructSelfSignedData(Ieee1609Dot2Data& etsi103097Signed, const ecdsa256::PrivateKey& privKey, const vanetza::ByteBuffer& tbsDataPayload)
{
  etsi103097Signed.protocolVersion = 3L;
  etsi103097Signed.content = vanetza::asn1::allocate<Ieee1609Dot2Content>();
  etsi103097Signed.content->present = Ieee1609Dot2Content_PR_signedData;
  etsi103097Signed.content->choice.signedData = vanetza::asn1::allocate<SignedData>();
  SignedData *signedData = etsi103097Signed.content->choice.signedData;
  signedData->hashId = HashAlgorithm_sha256;

  signedData->tbsData = vanetza::asn1::allocate<ToBeSignedData>();
  ConstructToBeSignedData(*signedData->tbsData, tbsDataPayload);

  signedData->signer.present = SignerIdentifier_PR_self;

  vanetza::ByteBuffer tbsDataBuf = vanetza::asn1::encode_oer(asn_DEF_ToBeSignedData, signedData->tbsData);
  Sha256Digest tbsDataDigest = calculate_sha256_digest(tbsDataBuf.data(), tbsDataBuf.size());
  Sha256Digest signerIdentifierDigest = calculate_sha256_digest(nullptr, 0);
  vanetza::ByteBuffer signatureInput(64);
  std::copy_n(tbsDataDigest.begin(), tbsDataDigest.size(), signatureInput.data());
  std::copy_n(signerIdentifierDigest.begin(), signerIdentifierDigest.size(), signatureInput.data() + 32);
  EcdsaSignature signature = backend.sign_data(privKey, signatureInput);

  signedData->signature.present = Signature_PR_ecdsaNistP256Signature;

  EccP256CurvePoint& rSig = signedData->signature.choice.ecdsaNistP256Signature.rSig;

  // Always in X only form from backend.sign_data()
  rSig.present = EccP256CurvePoint_PR_x_only;
  OCTET_STRING& xOnly = rSig.choice.x_only;
  OCTET_STRING_fromBuf(&xOnly, (char*)boost::get<X_Coordinate_Only>(signature.R).x.data(), boost::get<X_Coordinate_Only>(signature.R).x.size());

  OCTET_STRING& sSig = signedData->signature.choice.ecdsaNistP256Signature.sSig;
  OCTET_STRING_fromBuf(&sSig, (char*)signature.s.data(), signature.s.size());
}

void CertificateManager::ConstructEncryptedData(Ieee1609Dot2Data& etsi103097Encrypted, const vanetza::ByteBuffer& data, const EtsiTs103097Certificate_t* recipient, MessageEncryptionParams& params)
{
  // === ENCRYPT DATA ==========================================================
  backend.encrypt_aes(data, params.aes);

  vanetza::ByteBuffer recipientCertEncoded = vanetza::asn1::encode_oer(asn_DEF_CertificateBase, recipient);
  params.ecies.p1 = recipientCertEncoded;
  params.ecies.encryptionPubKey = GetEncryptionKey(*recipient);
  vanetza::ByteBuffer keyBuffer(params.aes.key.begin(), params.aes.key.end());
  backend.encrypt_ecies(keyBuffer, params.ecies);

  // === CONSTRUCT ENCRYPTED DATA ==============================================
  etsi103097Encrypted.protocolVersion = 3L;
  etsi103097Encrypted.content = vanetza::asn1::allocate<Ieee1609Dot2Content>();
  etsi103097Encrypted.content->present = Ieee1609Dot2Content_PR_encryptedData;
  EncryptedData& encryptedData = etsi103097Encrypted.content->choice.encryptedData;

  RecipientInfo* recipientInfo = vanetza::asn1::allocate<RecipientInfo>();
  recipientInfo->present = RecipientInfo_PR_certRecipInfo;

  HashedId8 hashId8 = CalculateCertificateDigest(*recipient);
  OCTET_STRING& recipientId = recipientInfo->choice.certRecipInfo.recipientId;
  OCTET_STRING_fromBuf(&recipientId, (char*)hashId8.data(), hashId8.size());
  
  recipientInfo->choice.certRecipInfo.encKey.present = EncryptedDataEncryptionKey_PR_eciesNistP256;

  OCTET_STRING& cipher = recipientInfo->choice.certRecipInfo.encKey.choice.eciesNistP256.c;
  OCTET_STRING_fromBuf(&cipher, (char*)params.ecies.cipher.data(), params.ecies.cipher.size());

  OCTET_STRING& tag = recipientInfo->choice.certRecipInfo.encKey.choice.eciesNistP256.t;
  OCTET_STRING_fromBuf(&tag, (char*)params.ecies.tag.data(), params.ecies.tag.size());

  if (params.ecies.ephemeralPubKey.y.back() % 2) {
    recipientInfo->choice.certRecipInfo.encKey.choice.eciesNistP256.v.present = EccP256CurvePoint_PR_compressed_y_1;
    OCTET_STRING& ephKey = recipientInfo->choice.certRecipInfo.encKey.choice.eciesNistP256.v.choice.compressed_y_1;
    OCTET_STRING_fromBuf(&ephKey, (char*)params.ecies.ephemeralPubKey.x.data(), params.ecies.ephemeralPubKey.x.size());
  }
  else {
    recipientInfo->choice.certRecipInfo.encKey.choice.eciesNistP256.v.present = EccP256CurvePoint_PR_compressed_y_0;
    OCTET_STRING& ephKey = recipientInfo->choice.certRecipInfo.encKey.choice.eciesNistP256.v.choice.compressed_y_0;
    OCTET_STRING_fromBuf(&ephKey, (char*)params.ecies.ephemeralPubKey.x.data(), params.ecies.ephemeralPubKey.x.size());
  }

  ASN_SEQUENCE_ADD(&encryptedData.recipients, recipientInfo);

  encryptedData.ciphertext.present = SymmetricCiphertext_PR_aes128ccm;

  OCTET_STRING& ciphertext = encryptedData.ciphertext.choice.aes128ccm.ccmCiphertext;
  OCTET_STRING_fromBuf(&ciphertext, (char*)params.aes.result.data(), params.aes.result.size());

  OCTET_STRING& nonce = encryptedData.ciphertext.choice.aes128ccm.nonce;
  OCTET_STRING_fromBuf(&nonce, (char*)params.aes.nonce.data(), params.aes.nonce.size());
}

vanetza::ByteBuffer CertificateManager::CreateEnrolmentRequest(MessageEncryptionParams& params)
{
  auto jan1st = std::chrono::system_clock::from_time_t(JAN12004);
  auto timestamp = std::chrono::system_clock::now();
  ecGenerationTime = std::chrono::duration_cast<std::chrono::microseconds>(timestamp - jan1st).count();

  // === CONSTRUCT ETSI TS 102 941 DATA ========================================
  vanetza::asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 {asn_DEF_EtsiTs102941Data};
  ConstructEtsiTs102941Data(*data102941, EtsiTs102941DataContent_PR_enrolmentRequest);
  vanetza::ByteBuffer data102941Buf = data102941.encode();

  // === CONSTRUCT OUTER SIGNED DATA ===========================================
  vanetza::asn1::asn1c_oer_wrapper<Ieee1609Dot2Data> etsi103097Signed { asn_DEF_Ieee1609Dot2Data };
  ConstructSelfSignedData(*etsi103097Signed, canonicalKeyPair.private_key, data102941Buf);
  vanetza::ByteBuffer etsi103097SignedBuf = etsi103097Signed.encode();

  // === CONSTRUCT ENCRYPTED DATA ==============================================
  vanetza::asn1::asn1c_oer_wrapper<EnrolmentRequestMessage_t> enrolmentRequest { asn_DEF_EnrolmentRequestMessage };
  ConstructEncryptedData(*enrolmentRequest, etsi103097SignedBuf, rca.ea.cert, params);

  return enrolmentRequest.encode();
}

bool CertificateManager::SendEnrolmentRequest(const vanetza::ByteBuffer& request, vanetza::ByteBuffer& response)
{
  cpr::Response r = cpr::Post(cpr::Url{rca.ea.accessPoint},
                              cpr::Body{(char *)request.data(), request.size()},
                              cpr::Header{{"Content-Type", "application/x-its-request"}});
  if (r.status_code >= 400) {
    // return false;
  }
  response.insert(response.begin(), r.text.begin(), r.text.end());

  return true;
}

bool CertificateManager::ParseEnrolmentResponse(const vanetza::ByteBuffer& response, MessageEncryptionParams& params)
{
  vanetza::asn1::asn1c_oer_wrapper<Ieee1609Dot2Data> enrolmentResponse { asn_DEF_Ieee1609Dot2Data };
  enrolmentResponse.decode(response);

  // Check symmetric encryption key hash.
  OCTET_STRING& responseSek = enrolmentResponse->content->choice.encryptedData.recipients.list.array[0]->choice.pskRecipInfo;
  HashedId8 responseSekHash;
  std::copy_n(responseSek.buf, responseSekHash.size(), responseSekHash.data());
  HashedId8 sekHash = GetSymmetricEncryptionKeyHash(params.aes);
  if (responseSekHash != sekHash) {
    std::cerr << "Hash of symmetric encryption key does not match." << std::endl;
    return false;
  }
  else {
    std::cout << "Hash of symmetric encryption key in response matches." << std::endl;
  }

  // Decrypt response.
  MessageEncryptionParams::AES responseParams;
  OCTET_STRING& ccmCipher = enrolmentResponse->content->choice.encryptedData.ciphertext.choice.aes128ccm.ccmCiphertext;
  vanetza::ByteBuffer ccmCipherBuf(ccmCipher.buf, ccmCipher.buf + ccmCipher.size);
  OCTET_STRING& ccmNonce = enrolmentResponse->content->choice.encryptedData.ciphertext.choice.aes128ccm.nonce;
  std::copy_n(ccmNonce.buf, responseParams.nonce.size(), responseParams.nonce.data());
  responseParams.key = params.aes.key;
  if (!backend.decrypt_aes(ccmCipherBuf, responseParams)) {
    std::cerr << "Decryption of enrolment response failed." << std::endl;
    return false;
  }
  else {
    std::cout << "Decryption of enrolment response succesful." << std::endl;
  }

  vanetza::asn1::asn1c_oer_wrapper<Ieee1609Dot2Data> signedResponse { asn_DEF_Ieee1609Dot2Data };
  signedResponse.decode(responseParams.result);

  SignedData* signedData = signedResponse->content->choice.signedData;

  // Check if cert in signed data has same hash as EA cert.
  EtsiTs103097Certificate_t* eaCert = rca.ea.cert;
  HashedId8 certHash = GetSignerDigest(*signedData);
  HashedId8 eaCertHash = CalculateCertificateDigest(*eaCert);
  if (certHash != eaCertHash) {
    std::cerr << "EA cert in signed data differs from saved EA cert" << std::endl;
    return false;
  }

  // Verify signed data.
  if (!VerifySignedData(*signedData, eaCert)) {
    std::cerr << "Verification of signed response failed." << std::endl;
    return false;
  }

  vanetza::asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 { asn_DEF_EtsiTs102941Data };
  vanetza::ByteBuffer data102941buf(signedData->tbsData->payload->data->content->choice.unsecuredData.buf,
                                    signedData->tbsData->payload->data->content->choice.unsecuredData.buf + signedData->tbsData->payload->data->content->choice.unsecuredData.size);
  data102941.decode(data102941buf);

  // Check response code.
  InnerEcResponse& innerEcResponse = data102941->content.choice.enrolmentResponse;
  if (innerEcResponse.responseCode != EnrolmentResponseCode_ok) {
    std::cerr << "Authorization response code not OK. Response code is: " << innerEcResponse.responseCode << std::endl;
    return false;
  }

  enrolmentCredential = (EtsiTs103097Certificate_t*)vanetza::asn1::copy(asn_DEF_EtsiTs103097Certificate, innerEcResponse.certificate);
  return true;
}

bool CertificateManager::RequestEc()
{
  MessageEncryptionParams params;
  std::cout << "Generating enrolment request message." << std::endl;
  vanetza::ByteBuffer ecRequest = CreateEnrolmentRequest(params);

  Sha256Digest ecReqDigest = calculate_sha256_digest(ecRequest.data(), ecRequest.size());

  vanetza::ByteBuffer ecResponse;
  std::cout << "Requesting enrolment credential." << std::endl;
  if (!SendEnrolmentRequest(ecRequest, ecResponse))
    return false;

  std::cout << "Received enrolment response message." << std::endl;
  if (!ParseEnrolmentResponse(ecResponse, params))
    return false;

  return true;
}

void CertificateManager::GenerateAtKeys(PublicVerificationKey& verKey)
{
  atVerKeyPair = backend.generate_key_pair();

  verKey.present = PublicVerificationKey_PR_ecdsaNistP256;
  if (atVerKeyPair.public_key.y.back() % 2) {
    verKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR_compressed_y_1;
    OCTET_STRING& verKeyStr = verKey.choice.ecdsaNistP256.choice.compressed_y_1;
    OCTET_STRING_fromBuf(&verKeyStr, (char*)atVerKeyPair.public_key.x.data(), atVerKeyPair.public_key.x.size());
  }
  else {
    verKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR_compressed_y_0;
    OCTET_STRING& verKeyStr = verKey.choice.ecdsaNistP256.choice.compressed_y_0;
    OCTET_STRING_fromBuf(&verKeyStr, (char*)atVerKeyPair.public_key.x.data(), atVerKeyPair.public_key.x.size());
  }

  vanetza::ByteBuffer verKeyBuf = vanetza::asn1::encode_oer(asn_DEF_PublicVerificationKey, &verKey);

  hmacKey = backend.generate_hmac_key();
  keyTag = create_hmac_tag(verKeyBuf, hmacKey);
}

void CertificateManager::ConstructSharedAtRequest(SharedAtRequest& sharedAtReq)
{
  HashedId8 eaCertHash = CalculateCertificateDigest(*rca.ea.cert);
  OCTET_STRING_fromBuf(&sharedAtReq.eaId, (char*)eaCertHash.data(), eaCertHash.size());

  OCTET_STRING_fromBuf(&sharedAtReq.keyTag, (char*)keyTag.data(), keyTag.size());

  sharedAtReq.certificateFormat = CertificateFormat_ts103097v131;

  sharedAtReq.requestedSubjectAttributes.appPermissions = vanetza::asn1::allocate<SequenceOfPsidSsp>();
  PsidSsp* caPermission = vanetza::asn1::allocate<PsidSsp>();
  caPermission->psid = vanetza::aid::CA;
  caPermission->ssp = vanetza::asn1::allocate<ServiceSpecificPermissions>();
  caPermission->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
  std::array<uint8_t, 3> caSspBitmap = {0x01, 0xFF, 0xFC};
  OCTET_STRING_fromBuf(&caPermission->ssp->choice.bitmapSsp, (char *)caSspBitmap.data(), caSspBitmap.size());
  ASN_SEQUENCE_ADD(sharedAtReq.requestedSubjectAttributes.appPermissions, caPermission);
  PsidSsp* denPermission = vanetza::asn1::allocate<PsidSsp>();
  denPermission->psid = vanetza::aid::DEN;
  denPermission->ssp = vanetza::asn1::allocate<ServiceSpecificPermissions>();
  denPermission->ssp->present = ServiceSpecificPermissions_PR_bitmapSsp;
  std::array<uint8_t, 4> denSspBitmap = {0x01, 0xFF, 0xFF, 0xFF};
  OCTET_STRING_fromBuf(&denPermission->ssp->choice.bitmapSsp, (char *)denSspBitmap.data(), denSspBitmap.size());
  ASN_SEQUENCE_ADD(sharedAtReq.requestedSubjectAttributes.appPermissions, denPermission);
  PsidSsp* gnMgmtPermission = vanetza::asn1::allocate<PsidSsp>();
  gnMgmtPermission->psid = vanetza::aid::GN_MGMT;
  gnMgmtPermission->ssp = nullptr;
  ASN_SEQUENCE_ADD(sharedAtReq.requestedSubjectAttributes.appPermissions, gnMgmtPermission);
}

void CertificateManager::ConstructSignedExternalPayload(Ieee1609Dot2Data& etsi103097SignedExtPayload, SharedAtRequest& sharedAtReq)
{
  etsi103097SignedExtPayload.protocolVersion = 3L;
  etsi103097SignedExtPayload.content = vanetza::asn1::allocate<Ieee1609Dot2Content>();
  etsi103097SignedExtPayload.content->present = Ieee1609Dot2Content_PR_signedData;
  etsi103097SignedExtPayload.content->choice.signedData = vanetza::asn1::allocate<SignedData>();
  SignedData* signedData = etsi103097SignedExtPayload.content->choice.signedData;
  signedData->hashId = HashAlgorithm_sha256;

  signedData->tbsData = vanetza::asn1::allocate<ToBeSignedData>();
  signedData->tbsData->payload = vanetza::asn1::allocate<SignedDataPayload>();
  signedData->tbsData->payload->data = nullptr;
  signedData->tbsData->payload->extDataHash = vanetza::asn1::allocate<HashedData>();
  signedData->tbsData->payload->extDataHash->present = HashedData_PR_sha256HashedData;

  vanetza::ByteBuffer sharedAtRequestBuf = vanetza::asn1::encode_per(asn_DEF_SharedAtRequest, &sharedAtReq);
  Sha256Digest sharedAtRequestHash = calculate_sha256_digest(sharedAtRequestBuf.data(), sharedAtRequestBuf.size());
  OCTET_STRING& hashedData = signedData->tbsData->payload->extDataHash->choice.sha256HashedData;
  OCTET_STRING_fromBuf(&hashedData, (char *)sharedAtRequestHash.data(), sharedAtRequestHash.size());

  signedData->tbsData->headerInfo.psid = vanetza::aid::SCR;
  
  auto jan1st = std::chrono::system_clock::from_time_t(JAN12004);
  auto timestamp = std::chrono::system_clock::now();
  uint64_t microseconds = std::chrono::duration_cast<std::chrono::microseconds>(timestamp - jan1st).count();
  signedData->tbsData->headerInfo.generationTime = vanetza::asn1::allocate<Time64_t>();
  asn_uint642INTEGER(signedData->tbsData->headerInfo.generationTime, microseconds);

  signedData->tbsData->headerInfo.encryptionKey = nullptr;
  signedData->tbsData->headerInfo.expiryTime = nullptr;
  signedData->tbsData->headerInfo.generationLocation = nullptr;
  signedData->tbsData->headerInfo.inlineP2pcdRequest = nullptr;
  signedData->tbsData->headerInfo.missingCrlIdentifier = nullptr;
  signedData->tbsData->headerInfo.p2pcdLearningRequest = nullptr;
  signedData->tbsData->headerInfo.requestedCertificate = nullptr;

  signedData->signer.present = SignerIdentifier_PR_digest;
  HashedId8 hashId8 = CalculateCertificateDigest(*enrolmentCredential); // EC certificate
  OCTET_STRING_fromBuf(&signedData->signer.choice.digest, (char*)hashId8.data(), hashId8.size());

  vanetza::ByteBuffer tbsDataBuf = vanetza::asn1::encode_oer(asn_DEF_ToBeSignedData, signedData->tbsData);
  Sha256Digest tbsDataDigest = calculate_sha256_digest(tbsDataBuf.data(), tbsDataBuf.size());
  vanetza::ByteBuffer ecBuf = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, enrolmentCredential);
  Sha256Digest signerIdentifierDigest = calculate_sha256_digest(ecBuf.data(), ecBuf.size());
  vanetza::ByteBuffer signatureInput(64);
  std::copy_n(tbsDataDigest.begin(), tbsDataDigest.size(), signatureInput.data());
  std::copy_n(signerIdentifierDigest.begin(), signerIdentifierDigest.size(), signatureInput.data() + 32);
  ecdsa256::PrivateKey privKey = verificationKeyPair.private_key; // Private key corresponding to EC's verification key
  EcdsaSignature signature = backend.sign_data(privKey, signatureInput);

  signedData->signature.present = Signature_PR_ecdsaNistP256Signature;

  EccP256CurvePoint& rSig = signedData->signature.choice.ecdsaNistP256Signature.rSig;

  // Signature always in X only form from backend.sign_data()
  rSig.present = EccP256CurvePoint_PR_x_only;
  OCTET_STRING& xOnly = rSig.choice.x_only;
  OCTET_STRING_fromBuf(&xOnly, (char*)boost::get<X_Coordinate_Only>(signature.R).x.data(), boost::get<X_Coordinate_Only>(signature.R).x.size());

  OCTET_STRING& sSig = signedData->signature.choice.ecdsaNistP256Signature.sSig;
  OCTET_STRING_fromBuf(&sSig, (char*)signature.s.data(), signature.s.size());
}

void CertificateManager::ConstructInnerAtRequest(InnerAtRequest& innerAt)
{
  GenerateAtKeys(innerAt.publicKeys.verificationKey);
  innerAt.publicKeys.encryptionKey = nullptr;

  OCTET_STRING_fromBuf(&innerAt.hmacKey, (char*)hmacKey.data(), hmacKey.size());

  ConstructSharedAtRequest(innerAt.sharedAtRequest);

  // === Construct signed external payload =====================================
  vanetza::asn1::asn1c_oer_wrapper<Ieee1609Dot2Data> signedExternalPayload {asn_DEF_EtsiTs103097Data_SignedExternalPayload};
  ConstructSignedExternalPayload(*signedExternalPayload, innerAt.sharedAtRequest);
  vanetza::ByteBuffer signedExternalPayloadBuf = signedExternalPayload.encode();

  // === Construct encrypted EC signature ======================================
  MessageEncryptionParams params;
  innerAt.ecSignature.present = EcSignature_PR_encryptedEcSignature;
  ConstructEncryptedData(innerAt.ecSignature.choice.encryptedEcSignature, signedExternalPayloadBuf, rca.ea.cert, params);
}

vanetza::ByteBuffer CertificateManager::CreateAuthorizationRequest(MessageEncryptionParams& params)
{
  // === CONSTRUCT ETSI TS 102 941 DATA ========================================
  vanetza::asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 {asn_DEF_EtsiTs102941Data};
  ConstructEtsiTs102941Data(*data102941, EtsiTs102941DataContent_PR_authorizationRequest);
  vanetza::ByteBuffer data102941Buf = data102941.encode();

  vanetza::asn1::asn1c_oer_wrapper<AuthorizationRequestMessageWithPop_t> authorizationRequest {asn_DEF_AuthorizationRequestMessageWithPop};
  ConstructEncryptedData(*authorizationRequest, data102941Buf, rca.aa.cert, params);

  return authorizationRequest.encode();
}

bool CertificateManager::SendAuthorizationRequest(const vanetza::ByteBuffer& request, vanetza::ByteBuffer& response)
{
  cpr::Response r = cpr::Post(cpr::Url{rca.aa.accessPoint},
                              cpr::Body{(char *)request.data(), request.size()},
                              cpr::Header{{"Content-Type", "application/x-its-request"}});
  if (r.status_code >= 400) {
    // return false;
  }
  response.insert(response.begin(), r.text.begin(), r.text.end());

  return true;
}

bool CertificateManager::ParseAuthorizationResponse(const vanetza::ByteBuffer& response, MessageEncryptionParams& params)
{
  vanetza::asn1::asn1c_oer_wrapper<Ieee1609Dot2Data> authorizationResponse {asn_DEF_Ieee1609Dot2Data};
  authorizationResponse.decode(response);

  MessageEncryptionParams::AES responseParams;
  OCTET_STRING& ccmCipher = authorizationResponse->content->choice.encryptedData.ciphertext.choice.aes128ccm.ccmCiphertext;
  vanetza::ByteBuffer ccmCipherBuf(ccmCipher.buf, ccmCipher.buf + ccmCipher.size);
  OCTET_STRING& ccmNonce = authorizationResponse->content->choice.encryptedData.ciphertext.choice.aes128ccm.nonce;
  std::copy_n(ccmNonce.buf, responseParams.nonce.size(), responseParams.nonce.data());
  responseParams.key = params.aes.key;
  if (!backend.decrypt_aes(ccmCipherBuf, responseParams)) {
    std::cerr << "Decryption of authorization response failed." << std::endl;
    return false;
  }
  else {
    std::cout << "Decryption of authorization response succesful." << std::endl;
  }

  vanetza::asn1::asn1c_oer_wrapper<Ieee1609Dot2Data> signedResponse { asn_DEF_Ieee1609Dot2Data };
  signedResponse.decode(responseParams.result);

  SignedData* signedData = signedResponse->content->choice.signedData;

  // Check if cert in signed data has same hash as AA cert.
  EtsiTs103097Certificate_t* aaCert = rca.aa.cert;
  HashedId8 certHash = GetSignerDigest(*signedData);
  HashedId8 aaCertHash = CalculateCertificateDigest(*aaCert);
  if (certHash != aaCertHash) {
    std::cout << "AA cert in signed data differs from saved AA cert" << std::endl;
    return false;
  }
  else {
    std::cout << "AA cert in response matches saved AA certificate." << std::endl;
  }

  // Verify signed data.
  if (!VerifySignedData(*signedData, aaCert)) {
    std::cerr << "Verification of signed response failed." << std::endl;
    return false;
  }
  else {
    std::cout << "Signature of response succesfuly verified." << std::endl;
  }

  vanetza::asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 { asn_DEF_EtsiTs102941Data };
  vanetza::ByteBuffer data102941buf(signedData->tbsData->payload->data->content->choice.unsecuredData.buf,
                                    signedData->tbsData->payload->data->content->choice.unsecuredData.buf + signedData->tbsData->payload->data->content->choice.unsecuredData.size);
  data102941.decode(data102941buf);

  // Check response code.
  InnerAtResponse& innerAtResponse = data102941->content.choice.authorizationResponse;
  printf("Authorization response code: %d\n", innerAtResponse.responseCode);
  if (innerAtResponse.responseCode != AuthorizationResponseCode_ok) {
    std::cerr << "Authorization response code not OK. Response code is: " << innerAtResponse.responseCode << std::endl;
    return false;
  }

  authorizationTicket = (EtsiTs103097Certificate_t*)vanetza::asn1::copy(asn_DEF_EtsiTs103097Certificate, innerAtResponse.certificate);
  return true;
}

bool CertificateManager::RequestAt()
{
  MessageEncryptionParams params;
  std::cout << "Generating authorization request message." << std::endl;
  vanetza::ByteBuffer atRequest = CreateAuthorizationRequest(params);

  vanetza::ByteBuffer atResponse;
  std::cout << "Requesting authorization ticket." << std::endl;
  if (!SendAuthorizationRequest(atRequest, atResponse))
    return false;

  std::cout << "Authorization response received." << std::endl;
  if (!ParseAuthorizationResponse(atResponse, params))
    return false;

  return true;
}

void CertificateManager::SaveVerificationKey(const std::string& path)
{
  CryptoPP::ByteQueue queue;
  CryptoPP::Integer x(verificationKeyPair.private_key.key.data(), verificationKeyPair.private_key.key.size());
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
  private_key.Initialize(CryptoPP::ASN1::secp256r1(), x);
  private_key.Save(queue);
  CryptoPP::FileSink file(path.c_str());
  queue.CopyTo(file);
  file.MessageEnd();
}

void CertificateManager::SaveEc(const std::string& path)
{
  if (!enrolmentCredential)
    return;

  std::ofstream stream(path, std::ios::out | std::ios::binary);
  vanetza::ByteBuffer ecBuf = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, enrolmentCredential);
  stream.write((char*)&ecBuf[0], ecBuf.size()); 
  stream.close();
}

void CertificateManager::LoadEc(EtsiTs103097Certificate_t* ec)
{
  enrolmentCredential = (EtsiTs103097Certificate_t*)vanetza::asn1::copy(asn_DEF_EtsiTs103097Certificate, ec);
}

void CertificateManager::SaveAt(const std::string& path)
{
  if (!authorizationTicket)
    return;

  std::ofstream stream(path, std::ios::out | std::ios::binary);
  vanetza::ByteBuffer atBuf = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, authorizationTicket);
  stream.write((char*)&atBuf[0], atBuf.size()); 
  stream.close();
}

HashedId8 CertificateManager::GetSymmetricEncryptionKeyHash(const MessageEncryptionParams::AES& aesParams)
{
  HashedId8 hid8;
  SymmetricEncryptionKey* sek = vanetza::asn1::allocate<SymmetricEncryptionKey>();
  sek->present = SymmetricEncryptionKey_PR_aes128Ccm;
  OCTET_STRING_fromBuf(&sek->choice.aes128Ccm, (char*)aesParams.key.data(), aesParams.key.size());
  vanetza::ByteBuffer recipInfoBuf = vanetza::asn1::encode_oer(asn_DEF_SymmetricEncryptionKey, sek);
  vanetza::asn1::free(asn_DEF_SymmetricEncryptionKey, sek);
  Sha256Digest digest = calculate_sha256_digest(recipInfoBuf.data(), recipInfoBuf.size());
  std::copy(digest.data() + 24, digest.end(), hid8.data());
  return hid8;
}
