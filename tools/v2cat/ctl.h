#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/asn1/pki/CtlFormat.h>
#include <vanetza/asn1/pki/ToBeSignedCrl.h>
#include <map>

static const char* ectlUrlL0 = "https://cpoc.jrc.ec.europa.eu/L0/";
static const char* ectlTlmPath = "/home/adam/Documents/skoda/vanetza/tools/v2cat/certs/TLMCert";

/// @brief Class for managing trust lists
class CertificateTrustListManager
{
public:
  struct Entry
  {
    EtsiTs103097Certificate_t* cert = nullptr;
    std::string accessPoint;
  };

  struct RcaEntry
  {
    EtsiTs103097Certificate_t* cert = nullptr;
    std::string dcUrl;
    Entry ea;
    Entry aa;
  };

  /// @brief Basic constructor, fetches ECTL TLM certificate.
  CertificateTrustListManager();

  /// @brief Constructor for use with root CA.
  /// @param rcaCert   Certificate of root CA.
  /// @param rcaDcUrl  URL of distribution centre for root CA.
  CertificateTrustListManager(vanetza::security::v3::Certificate& rcaCert, std::string& rcaDcUrl);

  /// @brief Destructor, frees the list.
  ~CertificateTrustListManager();

  /// @brief Get certificate trust list from root CA distribution centre.
  /// @param rcaHash Hash of root CA certificate.
  bool GetCtl(const vanetza::security::HashedId8& rcaHash);

  /// @brief Get delta certificate trust list from root CA distribution centre.
  /// @param rcaHash        Hash of root CA certificate.
  /// @param sequenceNumber Sequence number of last known list.
  bool GetDeltaCtl(const vanetza::security::HashedId8& rcaHash, unsigned sequenceNumber);

  /// @brief Get certificate revocation list from root CA distribution centre.
  /// @param rcaHash Hash of root CA certificate.
  bool GetCrl(const vanetza::security::HashedId8& rcaHash);

  /// @brief Get european certificate trust list.
  bool GetEctl();

  /// @brief Return RcaEntry from saved entries, this includes root CA
  /// certificate, certificate and access point for EA and AA
  /// @param rcaHash Hash of root CA certificate.
  /// @return        RcaEntry for this root CA.
  RcaEntry GetRca(const vanetza::security::HashedId8& rcaHash);

  /// @brief Print list of saved root CAs and all information about them.
  void PrintRca() const;

private:
  /// @brief Load ceritifcate of European TLM.
  void LoadEctlTlmCert();

  /// @brief Request a certificate trust list.
  /// @param url URL of endpoint.
  /// @return    Data of the response.
  vanetza::ByteBuffer RequestCtl(const std::string& url) const;

  /// @brief Request a certificate revocation list.
  /// @param url URL of endpoint.
  /// @return    Data of the response.
  vanetza::ByteBuffer RequestCrl(const std::string& url) const;

  /// @brief Request a certificate from distribution centre.
  /// @param url URL of endpoint.
  /// @return    Data of the response.
  vanetza::ByteBuffer RequestCert(const std::string& url) const;

  /// @brief Parse a CTL originating from RCA.
  /// @param ctl Certificate trust list.
  void ParseRcaCtl(const CtlFormat_t& ctl);

  /// @brief Parse a CRL originating from RCA.
  /// @param ctl Certificate revocation list.
  void ParseRcaCrl(const ToBeSignedCrl& crl);

  /// @brief Parse a CTL originating from TLM.
  /// @param ctl Certificate trust list.
  void ParseTlmCtl(const CtlFormat_t& ctl);

  /// @brief Add certificate of root certificate authority to list.
  /// @param ctl RCA certificate.
  void AddRca(EtsiTs103097Certificate_t& cert);

  /// @brief Remove certificate of root certificate authority from list.
  /// @param certHash HashedId8 of certificate to remove.
  /// @return         TRUE if certificate was removed, FALSE else.
  bool RemoveRca(const vanetza::security::HashedId8& certHash);

  /// @brief Add information about the enrolment authority of a RCA to list.
  /// @param rcaHash     HashedId8 of RCA.
  /// @param cert        Certificate of EA.
  /// @param accessPoint Access point of EA.
  void AddEa(const vanetza::security::HashedId8& rcaHash, EtsiTs103097Certificate_t& cert, std::string& accessPoint);

  /// @brief Add information about the authorization authority of a RCA to list.
  /// @param rcaHash     HashedId8 of RCA.
  /// @param cert        Certificate of AA.
  /// @param accessPoint Access point of AA.
  void AddAa(const vanetza::security::HashedId8& rcaHash, EtsiTs103097Certificate_t& cert, std::string& accessPoint);

  /// @brief Add information about the distribution centre of a RCA to list.
  /// @param certHash HashedId8 of RCA.
  /// @param dcUrl    URL of distribution centre of RCA.
  void AddDc(const vanetza::security::HashedId8& certHash, std::string& dcUrl);

private:
  std::map<vanetza::security::HashedId8, RcaEntry> rcaList; ///< List of RCA entries.
  unsigned ectlSequenceNumber; ///< Sequence number of last valid ECTL.
  vanetza::security::v3::Certificate ectlTlmCert; ///< Certificate of ECTL TLM.
};
