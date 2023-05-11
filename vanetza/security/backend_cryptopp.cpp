#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <cryptopp/oids.h>
#include <algorithm>
#include <cassert>
#include <iterator>
#include <functional>

namespace vanetza
{
namespace security
{

using std::placeholders::_1;

BackendCryptoPP::BackendCryptoPP() :
    m_private_cache(std::bind(&BackendCryptoPP::internal_private_key, this, _1), 8),
    m_public_cache(std::bind(&BackendCryptoPP::internal_public_key, this, _1), 2048)
{
}

EcdsaSignature BackendCryptoPP::sign_data(const ecdsa256::PrivateKey& generic_key, const ByteBuffer& data)
{
    return sign_data(m_private_cache[generic_key], data);
}

EcdsaSignature BackendCryptoPP::sign_data(const PrivateKey& private_key, const ByteBuffer& data)
{
    // calculate signature
    Signer signer(private_key);
    ByteBuffer signature(signer.MaxSignatureLength(), 0x00);
    auto signature_length = signer.SignMessage(m_prng, data.data(), data.size(), signature.data());
    signature.resize(signature_length);

    auto signature_delimiter = signature.begin();
    std::advance(signature_delimiter, 32);

    EcdsaSignature ecdsa_signature;
    // set R
    X_Coordinate_Only coordinate;
    coordinate.x = ByteBuffer(signature.begin(), signature_delimiter);
    ecdsa_signature.R = std::move(coordinate);
    // set s
    ByteBuffer trailer_field_buffer(signature_delimiter, signature.end());
    ecdsa_signature.s = std::move(trailer_field_buffer);

    return ecdsa_signature;
}

bool BackendCryptoPP::verify_data(const ecdsa256::PublicKey& generic_key, const ByteBuffer& msg, const EcdsaSignature& sig)
{
    const ByteBuffer sigbuf = extract_signature_buffer(sig);
    return verify_data(m_public_cache[generic_key], msg, sigbuf);
}

bool BackendCryptoPP::verify_data(const PublicKey& public_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    Verifier verifier(public_key);
    return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}


boost::optional<Uncompressed> BackendCryptoPP::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            decompress(p.x, 0x02);
            return true;
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            decompress(p.x, 0x03);
            return true;
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        void decompress(const ByteBuffer& x, ByteBuffer::value_type type)
        {
            ByteBuffer compact;
            compact.reserve(x.size() + 1);
            compact.push_back(type);
            std::copy(x.begin(), x.end(), std::back_inserter(compact));

            BackendCryptoPP::Point point;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group(CryptoPP::ASN1::secp256r1());
            group.GetCurve().DecodePoint(point, compact.data(), compact.size());

            result.x = x;
            result.y.resize(result.x.size());
            point.y.Encode(result.y.data(), result.y.size());
        }

        Uncompressed result;
    };

    DecompressionVisitor visitor;
    if (boost::apply_visitor(visitor, ecc_point)) {
        return visitor.result;
    } else {
        return boost::none;
    }
}

ecdsa256::KeyPair BackendCryptoPP::generate_key_pair()
{
    ecdsa256::KeyPair kp;
    auto private_key = generate_private_key();
    auto& private_exponent = private_key.GetPrivateExponent();
    assert(kp.private_key.key.size() >= private_exponent.ByteCount());
    private_exponent.Encode(kp.private_key.key.data(), kp.private_key.key.size());

    auto public_key = generate_public_key(private_key);
    auto& public_element = public_key.GetPublicElement();
    assert(kp.public_key.x.size() >= public_element.x.ByteCount());
    assert(kp.public_key.y.size() >= public_element.y.ByteCount());
    public_element.x.Encode(kp.public_key.x.data(), kp.public_key.x.size());
    public_element.y.Encode(kp.public_key.y.data(), kp.public_key.y.size());
    return kp;
}

BackendCryptoPP::PrivateKey BackendCryptoPP::generate_private_key()
{
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    PrivateKey private_key;
    private_key.Initialize(m_prng, oid);
    assert(private_key.Validate(m_prng, 3));
    return private_key;
}

BackendCryptoPP::PublicKey BackendCryptoPP::generate_public_key(const PrivateKey& private_key)
{
    PublicKey public_key;
    private_key.MakePublicKey(public_key);
    assert(public_key.Validate(m_prng, 3));
    return public_key;
}

BackendCryptoPP::PublicKey BackendCryptoPP::internal_public_key(const ecdsa256::PublicKey& generic)
{
    CryptoPP::Integer x { generic.x.data(), generic.x.size() };
    CryptoPP::Integer y { generic.y.data(), generic.y.size() };
    CryptoPP::ECP::Point q { x, y };

    BackendCryptoPP::PublicKey pub;
    pub.Initialize(CryptoPP::ASN1::secp256r1(), q);
    assert(pub.Validate(m_prng, 3));
    return pub;
}

BackendCryptoPP::PrivateKey BackendCryptoPP::internal_private_key(const ecdsa256::PrivateKey& generic)
{
    PrivateKey key;
    CryptoPP::Integer integer { generic.key.data(), generic.key.size() };
    key.Initialize(CryptoPP::ASN1::secp256r1(), integer);
    return key;
}

bool BackendCryptoPP::encrypt_aes(const ByteBuffer& data, MessageEncryptionParams::AES& params)
{
    // Generate random key A, 16 octets.
    m_prng.GenerateBlock(params.key.data(), params.key.size());

    // Generate random nonce n, 12 octets.
    m_prng.GenerateBlock(params.nonce.data(), params.nonce.size());

    AesEncryption encryption;
    encryption.SetKeyWithIV(params.key.data(), params.key.size(),
                            params.nonce.data(), params.nonce.size());
    encryption.SpecifyDataLengths(0, data.size(), 0);

    try {
        CryptoPP::VectorSource ss1(data, true,
            new CryptoPP::AuthenticatedEncryptionFilter(encryption,
                new CryptoPP::VectorSink(params.result)
            )
        );
    }
    catch (CryptoPP::Exception &e) {
        return false;
    }

    return true;
}

bool BackendCryptoPP::decrypt_aes(const ByteBuffer& data, MessageEncryptionParams::AES& params)
{
    AesDecryption decryption;
    decryption.SetKeyWithIV(params.key.data(), params.key.size(),
                            params.nonce.data(), params.nonce.size());
    decryption.SpecifyDataLengths(0, data.size() - 16, 0);

    try {
        CryptoPP::VectorSource ss2(data, true,
            new CryptoPP::AuthenticatedDecryptionFilter(decryption,
                new CryptoPP::VectorSink(params.result)
            )
        );
    }
    catch(CryptoPP::Exception& e) {
        return false;
    }

    return true;
}

void BackendCryptoPP::encrypt_ecies(const ByteBuffer& data, MessageEncryptionParams::ECIES& params)
{
    CryptoPP::DL_KeyAgreementAlgorithm_DH<CryptoPP::ECP::Point, CryptoPP::IncompatibleCofactorMultiplication> agreeAlg;
    CryptoPP::DL_KeyDerivationAlgorithm_P1363<CryptoPP::ECP::Point, false, CryptoPP::P1363_KDF2<CryptoPP::SHA256>> derivAlg;
    CryptoPP::DL_EncryptionAlgorithm_Xor<CryptoPP::HMAC<CryptoPP::SHA256>, false> encAlg;
    PublicKey pk = m_public_cache[params.encryptionPubKey];
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> groupParams = pk.AccessGroupParameters();

    // Generate ephemeral keypair.
    CryptoPP::Integer x(m_prng, CryptoPP::Integer::One(), groupParams.GetMaxExponent());
    CryptoPP::ECP::Point q = groupParams.ExponentiateBase(x);
    q.x.Encode(params.ephemeralPubKey.x.data(), params.ephemeralPubKey.x.size());
    q.y.Encode(params.ephemeralPubKey.y.data(), params.ephemeralPubKey.y.size());

    // Agree on shared secret.
    CryptoPP::ECP::Point z = agreeAlg.AgreeWithEphemeralPrivateKey(groupParams, pk.GetPublicPrecomputation(), x);

    // Derive keys.
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(digest, params.p1.data(), params.p1.size());
    CryptoPP::ConstByteArrayParameter p1(digest, CryptoPP::SHA256::DIGESTSIZE, true);
    CryptoPP::SecByteBlock derivedKey(48);
    derivAlg.Derive(groupParams, derivedKey, derivedKey.size(), z, q, CryptoPP::MakeParameters(CryptoPP::Name::KeyDerivationParameters(), p1));

    CryptoPP::byte* cipherKey = derivedKey.data();
    CryptoPP::byte* macKey = derivedKey.data() + data.size();

    // Calculate cipher.
    if (data.size()) {
        CryptoPP::xorbuf(params.cipher.data(), data.data(), cipherKey, data.size());
    }

    // Calculate tag.
    CryptoPP::HMAC<CryptoPP::SHA256> mac(macKey, 32);
    CryptoPP::byte tag[32];
    mac.Update(params.cipher.data(), data.size());
    mac.Final(tag);

    // Tag is truncated to leftmost 128 bits.
    std::copy_n(tag, params.tag.size(), params.tag.data());
}

KeyTag BackendCryptoPP::create_tag(const ByteBuffer& data, HmacKey& hmacKey)
{
    KeyTag keyTag;

    // Generate random 32 byte HMAC key.
    m_prng.GenerateBlock(hmacKey.data(), hmacKey.size());

    // Calculate tag.
    CryptoPP::HMAC<CryptoPP::SHA256> mac(hmacKey.data(), hmacKey.size());
    CryptoPP::byte tag[hmacKey.size()];
    mac.Update(data.data(), data.size());
    mac.Final(tag);

    // Tag is truncated to leftmost 128 bits.
    std::copy_n(tag, keyTag.size(), keyTag.data());
    return keyTag;
}

} // namespace security
} // namespace vanetza
