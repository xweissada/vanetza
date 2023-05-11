#ifndef BACKEND_CRYPTOPP_HPP_JQWA9MLZ
#define BACKEND_CRYPTOPP_HPP_JQWA9MLZ

#include <vanetza/common/lru_cache.hpp>
#include <vanetza/security/backend.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/ccm.h>

namespace vanetza
{
namespace security
{

class BackendCryptoPP : public Backend
{
public:
    using Ecdsa256 = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;
    using Ecdsa384 = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>;
    using PrivateKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
    using PublicKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;
    using Signer = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer;
    using Verifier = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier;
    using Point = CryptoPP::ECP::Point;
    using AesEncryption = CryptoPP::CCM<CryptoPP::AES>::Encryption;
    using AesDecryption = CryptoPP::CCM<CryptoPP::AES>::Decryption;

    static constexpr auto backend_name = "CryptoPP";

    BackendCryptoPP();

    /// \see Backend::sign_data
    EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data_buffer) override;

    /// \see Backend::verify_data
    bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) override;

    /// \see Backend::verify_digest
    bool verify_digest(const PublicKey&, const ByteBuffer& digest, const Signature&) override;

    /// \see Backend::decompress_point
    boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) override;

    /// \see Backend::calculate_hash
    ByteBuffer calculate_hash(KeyType, const ByteBuffer&) override;

    /**
     * \brief generate a private key and the corresponding public key
     * \return generated key pair
     */
    ecdsa256::KeyPair generate_key_pair();

    /**
     * \brief encrypt data with AES-CCM algorithm
     * \param data data to be encrypted
     * \param params key, nonce and result of encryption
     * \return true if encryption succeeded, false else
     */
    bool encrypt_aes(const ByteBuffer& data, MessageEncryptionParams::AES& params);

    /**
     * \brief decrypt data with AES-CCM algorithm
     * \param data data to be decrypted
     * \param params key, nonce and result of decryption
     * \return true if decryption succeeded, false else
     */
    bool decrypt_aes(const ByteBuffer& data, MessageEncryptionParams::AES& params);

    /**
     * \brief encrypt data with ECIES algorithm
     * \param data data to be encrypted
     * \param params public key and parameter P1 as input; ephemeral public key, ciphertext and authentication tag as output
    */
    void encrypt_ecies(const ByteBuffer& data, MessageEncryptionParams::ECIES& params);

    /**
     * \brief generate HMAC key and create HMAC tag on data
     * \param data data to be tagged
     * \param hmacKey generated HMAC key
     * \return tag of data generated with hmacKey
    */
    KeyTag create_tag(const ByteBuffer& data, HmacKey& hmacKey);

private:
    /// internal sign method using crypto++ private key
    EcdsaSignature sign_data(const Ecdsa256::PrivateKey& key, const ByteBuffer& data);

    /// internal verify method using crypto++ public key
    bool verify_data(const Ecdsa256::PublicKey& key, const ByteBuffer& data, const ByteBuffer& sig);

    /// create private key
    Ecdsa256::PrivateKey generate_private_key();

    /// derive public key from private key
    Ecdsa256::PublicKey generate_public_key(const Ecdsa256::PrivateKey&);

    /// adapt generic public key to internal structure
    Ecdsa256::PublicKey internal_public_key(const ecdsa256::PublicKey&);

    /// adapt generic private key to internal structure
    Ecdsa256::PrivateKey internal_private_key(const ecdsa256::PrivateKey&);

    CryptoPP::AutoSeededRandomPool m_prng;
    LruCache<ecdsa256::PrivateKey, Ecdsa256::PrivateKey> m_private_cache;
    LruCache<ecdsa256::PublicKey, Ecdsa256::PublicKey> m_public_cache;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_CRYPTOPP_HPP_JQWA9MLZ */
