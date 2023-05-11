#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <cassert>

namespace vanetza
{
namespace security
{
namespace openssl
{

void check(bool valid)
{
    if (!valid) {
        throw Exception();
    }
}

Exception::Exception() : Exception(ERR_get_error())
{
}

Exception::Exception(code_type err) :
    std::runtime_error(ERR_reason_error_string(err))
{
}

BigNumber::BigNumber() : bignum(BN_new())
{
    check(bignum != nullptr);
}

BigNumber::BigNumber(const uint8_t* arr, std::size_t len) : BigNumber()
{
    BN_bin2bn(arr, len, bignum);
}

BIGNUM* BigNumber::move()
{
    BIGNUM* ptr = nullptr;
    std::swap(ptr, bignum);
    return ptr;
}

BigNumber::~BigNumber()
{
    if (bignum) {
        BN_clear_free(bignum);
    }
}

BigNumberContext::BigNumberContext() : ctx(BN_CTX_new())
{
    check(ctx != nullptr);
    BN_CTX_start(ctx);
}

BigNumberContext::~BigNumberContext()
{
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

Point::Point(const EC_GROUP* group) : point(EC_POINT_new(group))
{
    check(point != nullptr);
}

Point::Point(Point&& other) : point(nullptr)
{
    std::swap(point, other.point);
}

Point& Point::operator=(Point&& other)
{
    std::swap(point, other.point);
    return *this;
}

Point::~Point()
{
    EC_POINT_free(point);
}

Group::Group(int nid) : group(EC_GROUP_new_by_curve_name(nid))
{
    check(group != nullptr);
}

Group::~Group()
{
    EC_GROUP_clear_free(group);
}

Signature::Signature(ECDSA_SIG* sig) : signature(sig)
{
    check(signature);
}

Signature::Signature(const EcdsaSignature& ecdsa) :
    Signature(convert_for_signing(ecdsa.R), ecdsa.s)
{
}

Signature::Signature(const security::Signature& sig) :
    Signature(sig.r, sig.s)
{
}

Signature::Signature(const ByteBuffer& r, const ByteBuffer& s) :
    signature(ECDSA_SIG_new())
{
    check(signature);
#if OPENSSL_API_COMPAT < 0x10100000L
    BN_bin2bn(r.data(), r.size(), signature->r);
    BN_bin2bn(s.data(), s.size(), signature->s);
#else
    BigNumber bn_r { r };
    BigNumber bn_s { s };
    // ownership of big numbers is transfered by calling ECDSA_SIG_set0!
    ECDSA_SIG_set0(signature, bn_r.move(), bn_s.move());
#endif
}

Signature::Signature(Signature&& other) : signature(nullptr)
{
    std::swap(signature, other.signature);
}

Signature& Signature::operator=(Signature&& other)
{
    std::swap(signature, other.signature);
    return *this;
}

Signature::~Signature()
{
    ECDSA_SIG_free(signature);
}

Key::Key() : eckey(EC_KEY_new())
{
    check(eckey);
}

Key::Key(int nid) : eckey(EC_KEY_new_by_curve_name(nid))
{
    check(eckey);
}

Key::Key(Key&& other) : eckey(nullptr)
{
    std::swap(eckey, other.eckey);
}

Key& Key::operator=(Key&& other)
{
    std::swap(eckey, other.eckey);
    return *this;
}

Key::~Key()
{
    EC_KEY_free(eckey);
}

Aes::Aes(const std::array<uint8_t, 16>& key, const std::array<uint8_t, 12>& nonce)
{
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, IV_LENGTH, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, NULL);
    EVP_EncryptInit_ex2(ctx, NULL, key.data(), nonce.data(), NULL);
}

ByteBuffer Aes::Encrypt(const ByteBuffer& data)
{
    int len;
    int ciphertext_len;
    ByteBuffer result(data.size() + TAG_LENGTH);

    EVP_EncryptUpdate(ctx, NULL, &len, NULL, data.size());

    EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), data.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, result.data() + ciphertext_len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LENGTH, result.data() + ciphertext_len);

    return result;
}

Aes::~Aes()
{
    EVP_CIPHER_CTX_free(ctx);
}

} // namespace openssl
} // namespace security
} // namespace vanetza
