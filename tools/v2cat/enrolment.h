#pragma once

#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/hmac.hpp>

#include <vanetza/asn1/pki/EtsiTs102941Data.h>
#include <vanetza/asn1/pki/InnerEcRequestSignedForPop.h>
#include <vanetza/asn1/pki/InnerEcRequest.h>

#include "ctl.h"

/// @brief Class for managing enrolment and authorization of ITS-S.
class CertificateManager
{
public:
  /// @brief Constructor.
  /// @param itssId            Canonical identifier of ITS-S registered in PKI.
  /// @param canonicalKeyPair  Canonical keypair of registered ITS-S.
  /// @param rca               Root certificate authority information.
  CertificateManager(const std::string& itssId,
                     const vanetza::security::ecdsa256::KeyPair& canonicalKeyPair,
                     const CertificateTrustListManager::RcaEntry& rca)
    : itssId(itssId), canonicalKeyPair(canonicalKeyPair), rca(rca),
      enrolmentCredential(nullptr), authorizationTicket(nullptr)
  {}

  /// @brief Request enrolment credential from enrolment authority.
  /// @return TRUE if request was succesful, FALSE else.
  bool RequestEc();

  /// @brief Request authorization ticket from authorization authority.
  /// @return TRUE if request was succesful, FALSE else.
  bool RequestAt();

  /// @brief Save verification key that was generated for the request.
  /// @param path Path where to save key.
  void SaveVerificationKey(const std::string& path);

  /// @brief Save enrolment credential received from enrolment response.
  /// @param path Path where to save EC.
  void SaveEc(const std::string& path);

  /// @brief Load enrolment credential.
  /// @param ec Enrolment Credential.
  void LoadEc(EtsiTs103097Certificate_t* ec);

  /// @brief Save authorization ticket received from authorization response.
  /// @param path Path where to save AT.
  void SaveAt(const std::string& path);

private:
  /// @brief Parse the received enrolment response.
  /// @param response Enrolment response.
  /// @param params Encryption parameters.
  /// @return TRUE if enrolment succeeded, FALSE else.
  bool ParseEnrolmentResponse(const vanetza::ByteBuffer& response, vanetza::security::MessageEncryptionParams& params);

  /// @brief Send enrolment request to EA.
  /// @param request Enrolment request.
  /// @param response Enrolment response.
  /// @return TRUE if response received, FALSE else.
  bool SendEnrolmentRequest(const vanetza::ByteBuffer& request, vanetza::ByteBuffer& response);

  /// @brief Create a enrolment request message.
  /// @param params Encryption parameters.
  /// @return Encrypted enrolment request message.
  vanetza::ByteBuffer CreateEnrolmentRequest(vanetza::security::MessageEncryptionParams& params);

  /// @brief Encrypt data and fill ASN.1 structure.
  /// @param etsi103097Encrypted ASN.1 structure to be filled
  /// @param data Data to be encrypted
  /// @param recipient Certificate of recipient.
  /// @param params Encryption parameters.
  void ConstructEncryptedData(Ieee1609Dot2Data& etsi103097Encrypted, const vanetza::ByteBuffer& data, const EtsiTs103097Certificate_t* recipient, vanetza::security::MessageEncryptionParams& params);

  /// @brief Construct ETSI TS 102 941 Data structure.
  /// @param data102941 ETSI TS 102 941 Data structure.
  /// @param contentType Type of content in structure.
  void ConstructEtsiTs102941Data(EtsiTs102941Data& data102941, EtsiTs102941DataContent_PR contentType);

  /// @brief Construct SignedData structure.
  /// @param etsi103097Signed SignedData structure.
  /// @param privKey Private key used for signing.
  /// @param tbsDataPayload ToBeSignedDataPayload structure.
  void ConstructSelfSignedData(Ieee1609Dot2Data& etsi103097Signed, const vanetza::security::ecdsa256::PrivateKey& privKey, const vanetza::ByteBuffer& tbsDataPayload);

  /// @brief Construct ToBeSigneData structure.
  /// @param tbsData ToBeSigneData structure.
  /// @param payload Payload of structure.
  void ConstructToBeSignedData(ToBeSignedData& tbsData, const vanetza::ByteBuffer& payload);

  /// @brief Construct InnerEcRequest structure.
  /// @param innerEc InnerEcRequest structure.
  void ConstructInnerEcRequest(InnerEcRequest& innerEc);

  /// @brief Parse the received authorization response.
  /// @param response Authorization response.
  /// @param params Message encryption parameters.
  /// @return TRUE if authorization succeeded, FALSE else.
  bool ParseAuthorizationResponse(const vanetza::ByteBuffer& response, vanetza::security::MessageEncryptionParams& params);

  /// @brief Send authorization request message to AA.
  /// @param request Authorization request.
  /// @param response Authorization response.
  /// @return TRUE if response received, FALSE else.
  bool SendAuthorizationRequest(const vanetza::ByteBuffer& request, vanetza::ByteBuffer& response);

  /// @brief Create authorization request message.
  /// @param params Encryption parameters.
  /// @return Encrypted authorization request message.
  vanetza::ByteBuffer CreateAuthorizationRequest(vanetza::security::MessageEncryptionParams& params);

  /// @brief Construct InnerAtRequest structure.
  /// @param innerAt InnerAtRequest structure.
  void ConstructInnerAtRequest(InnerAtRequest& innerAt);

  /// @brief Construct SignedExternalPayload structure.
  /// @param etsi103097SignedExtPayload SignedExternalPayload structure.
  /// @param sharedAtReq SharedAtRequest structure.
  void ConstructSignedExternalPayload(Ieee1609Dot2Data& etsi103097SignedExtPayload, SharedAtRequest& sharedAtReq);

  /// @brief Construct SharedAtRequest structure.
  /// @param sharedAtReq SharedAtRequest structure.
  void ConstructSharedAtRequest(SharedAtRequest& sharedAtReq);

  /// @brief Generate verification key for authorization ticket.
  /// @param verKey PublicVerificationKey structure.
  void GenerateAtKeys(PublicVerificationKey& verKey);

  /// @brief Get hashed value of SymmetricEncryptionKey structure.
  /// @param aesParams AES encryption parameters.
  /// @return HashedId8 of AES key in SymmetricEncryptionKey structure.
  vanetza::security::HashedId8 GetSymmetricEncryptionKeyHash(const vanetza::security::MessageEncryptionParams::AES& aesParams);

private:
  std::string itssId; ///< Canonical identifier of ITS-S.
  vanetza::security::ecdsa256::KeyPair canonicalKeyPair; ///< ITS-S keypair.
  vanetza::security::ecdsa256::KeyPair verificationKeyPair; ///< Verification keypair used for EC request signing.
  vanetza::security::BackendCryptoPP backend; ///< Cryptographic backend.
  CertificateTrustListManager::RcaEntry rca; ///< Root certificate authority.
  EtsiTs103097Certificate_t* enrolmentCredential; ///< Enrolment credential.
  EtsiTs103097Certificate_t* authorizationTicket; ///< Authorization ticket.
  uint64_t ecGenerationTime; ///< Generation time of EC Request

  vanetza::security::ecdsa256::KeyPair atVerKeyPair; ///< Verification keypair used for AT request signing.
  vanetza::security::HmacKey hmacKey; ///< HMAC key for AT request.
  vanetza::security::KeyTag keyTag; ///< Tag of public keys for AT request.
};
