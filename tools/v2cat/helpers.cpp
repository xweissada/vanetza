#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/asn1/asn1c_conversion.hpp>




#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/asn1/pki/CtlFormat.h>
#include <vanetza/asn1/pki/EtsiTs102941Data.h>
#include <vanetza/asn1/pki/InnerEcRequest.h>

#include <boost/variant/get.hpp>

#include <iostream>
#include <fstream>

#include "helpers.h"

using namespace vanetza::security;

HashedId8 CalculateCertificateDigest(const EtsiTs103097Certificate_t& cert)
{
  vanetza::ByteBuffer certBuf = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, &cert);

  HashedId8 id;

  if (cert.issuer.present == IssuerIdentifier_PR_sha256AndDigest ||
      (cert.issuer.present == IssuerIdentifier_PR_self &&
       cert.issuer.choice.self == HashAlgorithm_sha256)) {
    vanetza::security::Sha256Digest digest = vanetza::security::calculate_sha256_digest(certBuf.data(), certBuf.size());
    assert(digest.size() >= id.size());
    std::copy(digest.end() - id.size(), digest.end(), id.begin());
  }
  else {
    vanetza::security::Sha384Digest digest = vanetza::security::calculate_sha384_digest(certBuf.data(), certBuf.size());
    assert(digest.size() >= id.size());
    std::copy(digest.end() - id.size(), digest.end(), id.begin());
  }

  return id;
}

std::string HashedId8toString(const vanetza::security::HashedId8& hash)
{
  std::string hashString;
  for (const auto& byte: hash) {
    char hex[3];
    sprintf(hex, "%02X", byte);
    hashString.append(hex);
  }
  return hashString;
}

Uncompressed DecompressPoint(const EccP256CurvePoint& point)
{
  BackendCryptoPP backend;

  Uncompressed uncompressed;
  EccP256CurvePoint_PR ret = point.present;
  if (ret == EccP256CurvePoint_PR_x_only) {
    vanetza::ByteBuffer compressedBuf(
      point.choice.x_only.buf,
      point.choice.x_only.buf + point.choice.x_only.size
    );
    X_Coordinate_Only compressed {compressedBuf};
    uncompressed = boost::get<Uncompressed>(backend.decompress_point(compressed));
  }
  else if (ret == EccP256CurvePoint_PR_compressed_y_0) {
    vanetza::ByteBuffer compressedBuf(
      point.choice.compressed_y_0.buf,
      point.choice.compressed_y_0.buf + point.choice.compressed_y_0.size
    );
    Compressed_Lsb_Y_0 compressed {compressedBuf};
    uncompressed = boost::get<Uncompressed>(backend.decompress_point(compressed));
  }
  else if (ret == EccP256CurvePoint_PR_compressed_y_1) {
    vanetza::ByteBuffer compressedBuf(
      point.choice.compressed_y_1.buf,
      point.choice.compressed_y_1.buf + point.choice.compressed_y_1.size
    );
    Compressed_Lsb_Y_1 compressed {compressedBuf};
    uncompressed = boost::get<Uncompressed>(backend.decompress_point(compressed));
  }
  else if (ret == EccP256CurvePoint_PR_uncompressedP256) {
    uncompressed.x.assign(point.choice.uncompressedP256.x.buf,
                          point.choice.uncompressedP256.x.buf + point.choice.uncompressedP256.x.size);
    uncompressed.y.assign(point.choice.uncompressedP256.y.buf,
                          point.choice.uncompressedP256.y.buf + point.choice.uncompressedP256.y.size);
  }
  else {
    printf("Invalid choice in ECC point type.\n");
  }

  return uncompressed;
}

ecdsa256::PublicKey GetEncryptionKey(const EtsiTs103097Certificate_t& eaCertificate)
{
  BackendCryptoPP backend;

  EccP256CurvePoint& point = eaCertificate.toBeSigned.encryptionKey->publicKey.choice.eciesNistP256;

  Uncompressed uncompressed = DecompressPoint(point);

  return ecdsa256::create_public_key(uncompressed);
}

bool VerifySignedData(const SignedData& signedData, const EtsiTs103097Certificate_t* cert)
{
  vanetza::security::BackendCryptoPP backend;

  if (signedData.hashId != HashAlgorithm_sha256) {
    // SHA384 signature verification not implemented.
    return true;
  }

  vanetza::ByteBuffer signerIdentifierBuf;
  vanetza::security::Uncompressed uncompressed;
  if (signedData.signer.present == SignerIdentifier_PR_digest) {
    if (!cert) {
      std::cerr << "Signer is digest and certificate has not been provided." << std::endl;
      return false;
    }
    uncompressed = DecompressPoint(cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256);
    signerIdentifierBuf = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, cert);
  }
  else if (signedData.signer.present == SignerIdentifier_PR_certificate) {
    cert = (EtsiTs103097Certificate_t*)signedData.signer.choice.certificate.list.array[0];
    uncompressed = DecompressPoint(cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256);
    signerIdentifierBuf = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, cert);
  }
  else if (signedData.signer.present == SignerIdentifier_PR_self) {
    signedData.tbsData->payload->data->content->choice.unsecuredData;
    vanetza::ByteBuffer data(signedData.tbsData->payload->data->content->choice.unsecuredData.buf,
                    signedData.tbsData->payload->data->content->choice.unsecuredData.buf + signedData.tbsData->payload->data->content->choice.unsecuredData.size);
    vanetza::asn1::asn1c_oer_wrapper<InnerEcRequest> innerEc {asn_DEF_InnerEcRequest};
    innerEc.decode(data);
    uncompressed = DecompressPoint(innerEc->publicKeys.verificationKey.choice.ecdsaNistP256);
  }

  // Reconstruct signature input.
  vanetza::ByteBuffer tbsDataBuf = vanetza::asn1::encode_oer(asn_DEF_ToBeSignedData, signedData.tbsData);
  auto tbsDataDigest = vanetza::security::calculate_sha256_digest(tbsDataBuf.data(), tbsDataBuf.size());
  auto signerIdentifierDigest = vanetza::security::calculate_sha256_digest(signerIdentifierBuf.data(), signerIdentifierBuf.size());
  vanetza::ByteBuffer verificationInput(tbsDataDigest.size() + signerIdentifierDigest.size());
  std::copy(tbsDataDigest.data(), tbsDataDigest.data() + tbsDataDigest.size(), verificationInput.data());
  std::copy(signerIdentifierDigest.data(), signerIdentifierDigest.data() + signerIdentifierDigest.size(), verificationInput.data() + tbsDataDigest.size());

  // Get verification key.
  vanetza::security::ecdsa256::PublicKey pubVerKey = vanetza::security::ecdsa256::create_public_key(uncompressed);

  // Get signature.
  const OCTET_STRING& rSigBuf = signedData.signature.choice.ecdsaNistP256Signature.rSig.choice.x_only;
  vanetza::security::X_Coordinate_Only rSig;
  rSig.x.resize(rSigBuf.size);
  std::copy(rSigBuf.buf, rSigBuf.buf + rSigBuf.size, rSig.x.data());
  const OCTET_STRING& sSigBuf = signedData.signature.choice.ecdsaNistP256Signature.sSig;
  vanetza::ByteBuffer sSig(sSigBuf.buf, sSigBuf.buf + sSigBuf.size);
  vanetza::security::EcdsaSignature sig;
  sig.R = std::move(rSig);
  sig.s = std::move(sSig);

  return backend.verify_data(pubVerKey, verificationInput, sig);
}

HashedId8 GetSignerDigest(const SignedData& signedData)
{
  HashedId8 digest;

  if (signedData.signer.present == SignerIdentifier_PR_digest) {
    std::copy_n(signedData.signer.choice.digest.buf, digest.size(), digest.begin());
  }
  else if (signedData.signer.present == SignerIdentifier_PR_certificate) {
    EtsiTs103097Certificate_t* cert = (EtsiTs103097Certificate_t *)signedData.signer.choice.certificate.list.array[0];
    digest = CalculateCertificateDigest(*cert);
  }

  return digest;
}

void LoadCertificate(const std::string& path, EtsiTs103097Certificate_t* cert)
{
  std::ifstream stream(path, std::ios::in | std::ios::binary);
  vanetza::ByteBuffer buf((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  vanetza::asn1::decode_oer(asn_DEF_EtsiTs103097Certificate, (void**)&cert, buf);
}
