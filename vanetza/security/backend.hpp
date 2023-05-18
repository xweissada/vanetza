#ifndef BACKEND_HPP_ZMRDTY2O
#define BACKEND_HPP_ZMRDTY2O

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/factory.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/signature.hpp>
#include <boost/optional/optional.hpp>
#include <memory>
#include <string>

namespace vanetza
{
namespace security
{

struct MessageEncryptionParams
{
    struct AES
    {
        std::array<uint8_t, 16> key;    ///< Key used for encryption.
        std::array<uint8_t, 12> nonce;  ///< Nonce/IV used for encryption.
        vanetza::ByteBuffer result;     ///< Ciphertext or plaintext result.
    };

    struct ECIES
    {
        ecdsa256::PublicKey encryptionPubKey;
        vanetza::ByteBuffer p1;
        ecdsa256::PublicKey ephemeralPubKey;  ///< Ephemeral public key.
        std::array<uint8_t, 16> cipher;       ///< Encryption ciphertext.
        std::array<uint8_t, 16> tag;          ///< Authentication tag.
    };

    AES aes;
    ECIES ecies;
};

/**
 * Interface to cryptographic features
 */
class Backend
{
public:
    /**
     * \brief calculate signature for given data and private key
     *
     * \param private_key Secret private key
     * \param data buffer with plaintext data
     * \return calculated signature
     */
    virtual EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data) = 0;

    /**
     * \brief try to verify data using public key and signature
     *
     * \param public_key Public key
     * \param data plaintext
     * \param sig signature of data
     * \return true if the data could be verified
     */
    virtual bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) = 0;

    /**
     * \brief decompress a possibly compressed elliptic curve point
     *
     * \param ecc_point elliptic curve point
     * \return uncompressed point
     */
    virtual boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) = 0;

    virtual ~Backend() = default;
};

/**
 * \brief get factory containing builtin backend implementations
 *
 * Included set of backends depends on CMake build configuration.
 * At least the "Null" backend is always included.
 * \return factory
 */
const Factory<Backend>& builtin_backends();

/**
 * \brief create a backend instance
 *
 * A backend named "default" is guaranteed not to return a nullptr.
 * However, it might be a dummy backend.
 *
 * \param name identifying name of backend implementation
 * \param factory build backend registered by name from this factory
 * \return backend instance (if available) or nullptr
 */
std::unique_ptr<Backend> create_backend(const std::string& name, const Factory<Backend>& = builtin_backends());

} // namespace security
} // namespace vanetza

#endif /* BACKEND_HPP_ZMRDTY2O */

