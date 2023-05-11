#pragma once

#include <vanetza/common/byte_buffer.hpp>

#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/basic_elements.hpp>

#include <vanetza/asn1/pki/EtsiTs103097Certificate.h>
#include <vanetza/asn1/pki/SignedData.h>

#define JAN12004 1072915200 // unix time of 00:00:00 UTC, 1 January, 2004

/// @brief Calculate the HashedId8 of a certificate.
/// @param cert     Certificate.
/// @return         HashedId8 of certificate.
vanetza::security::HashedId8 CalculateCertificateDigest(const EtsiTs103097Certificate_t& cert);

/// @brief Convert a HashedId8 to a string.
/// @param hash     HashedId8.
/// @return         String representation of HashedId8.
std::string HashedId8toString(const vanetza::security::HashedId8& hash);

/// @brief Decompress a possibly compressed elliptic curve point.
/// @param point    Elliptic curve point.
/// @return         Uncompressed point.
vanetza::security::Uncompressed DecompressPoint(const EccP256CurvePoint& point);

/// @brief Get encryption key out of a certificate.
/// @param eaCertificate  Certificate.
/// @return               Public encryption key.
vanetza::security::ecdsa256::PublicKey GetEncryptionKey(const EtsiTs103097Certificate_t& eaCertificate);

/// @brief Verify signature of signed data.
/// @param signedData     Signed data.
/// @param cert           Certificate containing verification key, only needed if not included in signed data.
/// @return               True if signature was verified succesfuly, false else.
bool VerifySignedData(const SignedData& signedData, const EtsiTs103097Certificate_t* cert = nullptr);

/// @brief Get HashedId8 of signed data.
/// @param signedData     Signed data.
/// @return               HashedId8
vanetza::security::HashedId8 GetSignerDigest(const SignedData& signedData);

/// @brief Load certificate from file and fill ASN.1 structure with its content.
/// @param path     Path to certificate.
/// @param cert     ASN.1 structure to parse into.
void LoadCertificate(const std::string& path, EtsiTs103097Certificate_t* cert);
