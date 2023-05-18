#include <iostream>

#include <cpr/cpr.h>

#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/backend_cryptopp.hpp>

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/pki/RcaCertificateTrustListMessage.h>
#include <vanetza/asn1/pki/TlmCertificateTrustListMessage.h>
#include <vanetza/asn1/pki/ToBeSignedRcaCtl.h>
#include <vanetza/asn1/pki/EtsiTs103097Certificate.h>
#include <vanetza/asn1/pki/EtsiTs102941Data.h>

#include <boost/filesystem.hpp>

#include "ctl.h"
#include "helpers.h"

using namespace vanetza;

CertificateTrustListManager::CertificateTrustListManager() :
  ectlSequenceNumber(0)
{
  LoadEctlTlmCert();
}

CertificateTrustListManager::CertificateTrustListManager(EtsiTs103097Certificate_t& rcaCert, std::string& rcaDcUrl) :
  ectlSequenceNumber(0), ectlTlmCert(nullptr)
{
  security::HashedId8 hash = CalculateCertificateDigest(rcaCert);
  AddRca(rcaCert);
  AddDc(hash, rcaDcUrl);
}

CertificateTrustListManager::~CertificateTrustListManager()
{
  for (auto& rca: rcaList) {
    asn1::free(asn_DEF_EtsiTs103097Certificate, rca.second.cert);
    if (rca.second.ea.cert != nullptr) {
      asn1::free(asn_DEF_EtsiTs103097Certificate, rca.second.ea.cert);
    }
    if (rca.second.aa.cert != nullptr) {
      asn1::free(asn_DEF_EtsiTs103097Certificate, rca.second.aa.cert);
    }
  }

  asn1::free(asn_DEF_EtsiTs103097Certificate, ectlTlmCert);
}

void CertificateTrustListManager::LoadEctlTlmCert()
{
  ByteBuffer ectlTlmCertBuf;
  if (false) {
    // Load ECTL TLM certificate from file.
    std::cout << "Loading ECTL TLM Certificate from file." << std::endl;
    std::ifstream stream(ectlTlmPath, std::ios::in | std::ios::binary);
    ectlTlmCertBuf.assign((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  }
  else {
    // Request ECTL TLM certificate and save it to file.
    std::string url = ectlUrlL0 + std::string("gettlmcertificate");
    std::cout << "Requesting ECTL TLM certificate from " << url << std::endl;
    ectlTlmCertBuf = RequestCert(url);
    std::ofstream stream(ectlTlmPath, std::ios::out | std::ios::binary);
    stream.write((char*)&ectlTlmCertBuf[0], ectlTlmCertBuf.size());
    stream.close();
  }
  ectlTlmCert = asn1::allocate<EtsiTs103097Certificate_t>();
  asn1::decode_oer(asn_DEF_EtsiTs103097Certificate, (void **)&ectlTlmCert, ectlTlmCertBuf);

  std::cout << "Got TLM certificate: " << ectlTlmCert->toBeSigned.id.choice.name.buf << std::endl;
}

void CertificateTrustListManager::AddRca(EtsiTs103097Certificate_t& cert)
{
  security::HashedId8 certHash = CalculateCertificateDigest(cert);

  auto it = rcaList.find(certHash);
  if (it != rcaList.end()) {
    it->second.cert = (EtsiTs103097Certificate_t *)asn1::copy(asn_DEF_EtsiTs103097Certificate, &cert);
  }
  else {
    RcaEntry entry;
    entry.cert = (EtsiTs103097Certificate_t *)asn1::copy(asn_DEF_EtsiTs103097Certificate, &cert);
    rcaList.insert(std::pair<security::HashedId8, RcaEntry>(certHash, entry));
  }
}

bool CertificateTrustListManager::RemoveRca(const security::HashedId8& certHash)
{
  auto rca = rcaList.find(certHash);
  if (rca != rcaList.end()) {
    asn1::free(asn_DEF_EtsiTs103097Certificate, rca->second.cert);
    if (rca->second.ea.cert != nullptr) {
      asn1::free(asn_DEF_EtsiTs103097Certificate, rca->second.ea.cert);
    }
    if (rca->second.aa.cert != nullptr) {
      asn1::free(asn_DEF_EtsiTs103097Certificate, rca->second.aa.cert);
    }
  }
  return rcaList.erase(certHash);
}

void CertificateTrustListManager::PrintRca() const
{
  for (const auto& entry: rcaList) {
    std::cout << HashedId8toString(entry.first) << std::endl;
    if (entry.second.cert->toBeSigned.id.present == CertificateId_PR_name &&
        entry.second.cert->toBeSigned.id.choice.name.size) {
      std::cout << "  Name: " << entry.second.cert->toBeSigned.id.choice.name.buf << std::endl;
    }
    if (!entry.second.dcUrl.empty()) {
      std::cout << "  DC url: " <<  entry.second.dcUrl << std::endl;
    }
    if (!entry.second.ea.accessPoint.empty()) {
      std::cout << "  EA url: " <<  entry.second.ea.accessPoint << std::endl;
    }
    if (!entry.second.aa.accessPoint.empty()) {
      std::cout << "  AA url: " <<  entry.second.aa.accessPoint << std::endl;
    }
    std::cout << std::endl;
  }
}

void CertificateTrustListManager::AddEa(const security::HashedId8& rcaHash, EtsiTs103097Certificate_t& cert, std::string& accessPoint)
{
  auto it = rcaList.find(rcaHash);
  if (it != rcaList.end()) {
    it->second.ea.cert = (EtsiTs103097Certificate_t *)asn1::copy(asn_DEF_EtsiTs103097Certificate, &cert);
    it->second.ea.accessPoint = std::move(accessPoint);
  }
  else {
    std::cerr << "Root CA of EA not found." << std::endl;
  }
}

void CertificateTrustListManager::AddAa(const security::HashedId8& rcaHash, EtsiTs103097Certificate_t& cert, std::string& accessPoint)
{
  auto it = rcaList.find(rcaHash);
  if (it != rcaList.end()) {
    it->second.aa.cert = (EtsiTs103097Certificate_t *)asn1::copy(asn_DEF_EtsiTs103097Certificate, &cert);
    it->second.aa.accessPoint = std::move(accessPoint);
  }
  else {
    std::cerr << "Root CA of AA not found." << std::endl;
  }
}

void CertificateTrustListManager::AddDc(const security::HashedId8& certHash, std::string& dcUrl)
{
  auto it = rcaList.find(certHash);
  if (it != rcaList.end()) {
    if (dcUrl.back() != '/')
      dcUrl.push_back('/');
    it->second.dcUrl = std::move(dcUrl);
  }
  else {
    std::cerr << "Root CA of DC not found." << std::endl;
  }
}

void CertificateTrustListManager::ParseRcaCtl(const CtlFormat_t& ctl)
{
  for (unsigned i = 0; i < ctl.ctlCommands.list.count; i++) {
    if (ctl.ctlCommands.list.array[i]->present == CtlCommand_PR_add) {
      if (ctl.ctlCommands.list.array[i]->choice.add.present == CtlEntry_PR_ea) {
        EaEntry_t ea = ctl.ctlCommands.list.array[i]->choice.add.choice.ea;
        EtsiTs103097Certificate_t& cert = ea.eaCertificate;

        security::HashedId8 rcaHash;
        std::copy_n(cert.issuer.choice.sha256AndDigest.buf, rcaHash.size(), rcaHash.begin());

        std::string accessPoint;
        if (ctl.ctlCommands.list.array[i]->choice.add.choice.ea.itsAccessPoint) {
          accessPoint.assign((char *)ea.itsAccessPoint->buf, ea.itsAccessPoint->size);
        }
        AddEa(rcaHash, cert, accessPoint);
      }
      else if (ctl.ctlCommands.list.array[i]->choice.add.present == CtlEntry_PR_aa) {
        AaEntry_t aa = ctl.ctlCommands.list.array[i]->choice.add.choice.aa;
        EtsiTs103097Certificate_t& cert = aa.aaCertificate;

        security::HashedId8 rcaHash;
        std::copy_n(cert.issuer.choice.sha256AndDigest.buf, rcaHash.size(), rcaHash.begin());

        std::string accessPoint((char *)aa.accessPoint.buf, aa.accessPoint.size);
        AddAa(rcaHash, cert, accessPoint);
      }
      else if (ctl.ctlCommands.list.array[i]->choice.add.present == CtlEntry_PR_dc) {
        DcEntry_t& dc = ctl.ctlCommands.list.array[i]->choice.add.choice.dc;
        for (unsigned i = 0; i < dc.cert.list.count; i++) {
          security::HashedId8 certHashedId8;
          std::copy(dc.cert.list.array[i]->buf,
                    dc.cert.list.array[i]->buf + dc.cert.list.array[i]->size,
                    certHashedId8.data());

          std::string dcUrl((char *)dc.url.buf);
          AddDc(certHashedId8, dcUrl);
        }
      }
      else {
        // Only EA, AA or DC entries allowed in RCA CTL.
        std::cerr << "Disallowed entry in RCA CTL." << std::endl;
      }
    }
    else if (ctl.ctlCommands.list.array[i]->present == CtlCommand_PR_delete) {
      security::HashedId8 rcaHash;
      std::copy_n(ctl.ctlCommands.list.array[i]->choice.Delete.choice.cert.buf,
                  rcaHash.size(),
                  rcaHash.begin());
      RemoveRca(rcaHash);
    }
  }
}

void CertificateTrustListManager::ParseRcaCrl(const ToBeSignedCrl& crl)
{
  for (unsigned i = 0; i < crl.entries.list.count; i++) {
    security::HashedId8 revokedRcaHash;
    std::copy_n(crl.entries.list.array[i]->buf, revokedRcaHash.size(), revokedRcaHash.begin());
    RemoveRca(revokedRcaHash);
  }
}

void CertificateTrustListManager::ParseTlmCtl(const CtlFormat_t& ctl)
{
  ectlSequenceNumber = ctl.ctlSequence;

  for (unsigned i = 0; i < ctl.ctlCommands.list.count; i++) {
    if (ctl.ctlCommands.list.array[i]->choice.add.present == CtlEntry_PR_rca) {
      EtsiTs103097Certificate_t& cert = ctl.ctlCommands.list.array[i]->choice.add.choice.rca.selfsignedRootCa;
      ByteBuffer certBuf = asn1::encode_oer(asn_DEF_Certificate, &cert);
      AddRca(cert);
    }
    else if (ctl.ctlCommands.list.array[i]->choice.add.present == CtlEntry_PR_dc) {
      DcEntry_t& dc = ctl.ctlCommands.list.array[i]->choice.add.choice.dc;
      for (unsigned i = 0; i < dc.cert.list.count; i++) {
        security::HashedId8 certHashedId8;
        std::copy(dc.cert.list.array[i]->buf, dc.cert.list.array[i]->buf + dc.cert.list.array[i]->size, certHashedId8.data());
        std::string dcUrl((char *)dc.url.buf);
        AddDc(certHashedId8, dcUrl);
      }
    }
    else if (ctl.ctlCommands.list.array[i]->choice.add.present == CtlEntry_PR_tlm) {
      EtsiTs103097Certificate_t& cert = ctl.ctlCommands.list.array[i]->choice.add.choice.tlm.selfSignedTLMCertificate;
      ByteBuffer certBuf = asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, &cert);
      security::HashedId8 certHash = CalculateCertificateDigest(cert);
      security::HashedId8 tlmCertHash = CalculateCertificateDigest(*ectlTlmCert);
      if (certHash != tlmCertHash) {
        std::cerr << "TLM certificate in ECTL does not match correct TLM" << std::endl;
      }
    }
    else {
      // Only TLM, RCA or DC allowed in TLM CTL.
      std::cerr << "Disallowed entry in TLM CTL." << std::endl;
    }
  }
}

ByteBuffer CertificateTrustListManager::RequestCert(const std::string& url) const
{
  cpr::Response r = cpr::Get(cpr::Url{url},
                             cpr::Header{{"Content-Type", "application/octet-stream"}});

  if (r.status_code >= 400) {
    std::cerr << "RESPONSE CODE: " << r.status_code << std::endl;
    std::cerr << "RAW HEADER: " << r.raw_header << std::endl;
  }

  return ByteBuffer(r.text.begin(), r.text.end());
}

ByteBuffer CertificateTrustListManager::RequestCtl(const std::string& url) const
{
  cpr::Response r = cpr::Get(cpr::Url{url},
                             cpr::Header{{"Content-Type", "application/x-its-ctl"}});

  if (r.status_code >= 400) {
    std::cerr << "RESPONSE CODE: " << r.status_code << std::endl;
    std::cerr << "RAW HEADER: " << r.raw_header << std::endl;
  }

  return ByteBuffer(r.text.begin(), r.text.end());
}

ByteBuffer CertificateTrustListManager::RequestCrl(const std::string& url) const
{
  cpr::Response r = cpr::Get(cpr::Url{url},
                             cpr::Header{{"Content-Type", "application/x-its-crl"}});

  if (r.status_code >= 400) {
    std::cerr << "RESPONSE CODE: " << r.status_code << std::endl;
    std::cerr << "RAW HEADER: " << r.raw_header << std::endl;
  }

  return ByteBuffer(r.text.begin(), r.text.end());
}

bool CertificateTrustListManager::GetCtl(const security::HashedId8& rcaHash)
{
  auto rca = rcaList.find(rcaHash);
  if (rca == rcaList.end()) {
    std::cerr << "RCA not found." << std::endl;
    return false;
  }

  std::string url = rca->second.dcUrl + std::string("getctl/") + HashedId8toString(rcaHash);
  std::cout << "Requesting CTL from " << url << std::endl;
  ByteBuffer ctlBuf = RequestCtl(url);
  std::cout << "Got response with CTL" << std::endl;

  asn1::asn1c_oer_wrapper<RcaCertificateTrustListMessage_t> ctl {asn_DEF_RcaCertificateTrustListMessage};
  ctl.decode(ctlBuf);

  if (ctl->content->present != Ieee1609Dot2Content_PR_signedData) {
    std::cerr << "Invalid CTL." << std::endl;
    return false;
  }

  SignedData* sd = ctl->content->choice.signedData;

  // Check if cert in signed data has same hash as RCA.
  security::HashedId8 certHash = GetSignerDigest(*sd);
  if (certHash != rcaHash) {
    std::cerr << "Hash of RCA in CTL differs from saved RCA hash." << std::endl;
    return false;
  }
  else {
    std::cout << "Hash of RCA certificate matches hash in received CTL." << std::endl;
  }

  // Verify signature.
  if (!VerifySignedData(*sd)) {
    std::cerr << "Signed data could not be verified." << std::endl;
    return false;
  }
  else {
    std::cout << "Signature of CTL verified succesfuly." << std::endl;
  }

  OCTET_STRING& unsecuredData = sd->tbsData->payload->data->content->choice.unsecuredData;
  ByteBuffer data(unsecuredData.buf,
                  unsecuredData.buf + unsecuredData.size);

  asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 {asn_DEF_EtsiTs102941Data};
  data102941.decode(data);

  CtlFormat_t& tbsCtl = data102941->content.choice.certificateTrustListRca;

  ParseRcaCtl(tbsCtl);

  return true;
}

bool CertificateTrustListManager::GetDeltaCtl(const security::HashedId8& rcaHash, unsigned sequenceNumber)
{
  auto rca = rcaList.find(rcaHash);
  if (rca == rcaList.end()) {
    std::cerr << "RCA not found." << std::endl;
    return false;
  }

  std::string url = rca->second.dcUrl + std::string("getctl/") + HashedId8toString(rcaHash) + std::to_string(sequenceNumber);
  std::cout << "Requesting delta CTL from " << url << std::endl;
  ByteBuffer ctlBuf = RequestCtl(url);

  asn1::asn1c_oer_wrapper<RcaCertificateTrustListMessage_t> ctl {asn_DEF_RcaCertificateTrustListMessage};
  ctl.decode(ctlBuf);

  SignedData* sd = ctl->content->choice.signedData;

  // Check if cert in signed data has same hash as RCA.
  security::HashedId8 certHash = GetSignerDigest(*sd);
  if (certHash != rcaHash) {
    std::cerr << "Hash of RCA in CTL differs from saved RCA hash." << std::endl;
    return false;
  }
  else {
    std::cout << "Hash of RCA certificate matches received hash." << std::endl;
  }

  // Verify signature.
  if (!VerifySignedData(*sd)) {
    std::cerr << "Signed data could not be verified." << std::endl;
    return false;
  }
  else {
    std::cout << "Signature verified succesfuly." << std::endl;
  }

  OCTET_STRING& unsecuredData = sd->tbsData->payload->data->content->choice.unsecuredData;
  ByteBuffer data(unsecuredData.buf,
                  unsecuredData.buf + unsecuredData.size);

  asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 {asn_DEF_EtsiTs102941Data};
  data102941.decode(data);

  CtlFormat_t& tbsCtl = data102941->content.choice.certificateTrustListRca;

  ParseRcaCtl(tbsCtl);

  return true;
}

bool CertificateTrustListManager::GetCrl(const security::HashedId8& rcaHash)
{
  auto rca = rcaList.find(rcaHash);
  if (rca == rcaList.end()) {
    std::cerr << "RCA not found." << std::endl;
    return false;
  }

  std::string url = rca->second.dcUrl + std::string("getcrl/") + HashedId8toString(rcaHash);
  std::cout << "Requesting CRL from " << url << std::endl;
  ByteBuffer crlBuf = RequestCtl(url);

  asn1::asn1c_oer_wrapper<RcaCertificateTrustListMessage_t> crl {asn_DEF_RcaCertificateTrustListMessage};
  crl.decode(crlBuf);

  SignedData* sd = crl->content->choice.signedData;

  // Check if cert in signed data has same hash as RCA.
  security::HashedId8 certHash = GetSignerDigest(*sd);
  if (certHash != rcaHash) {
    std::cerr << "Hash of RCA in CTL differs from saved RCA hash." << std::endl;
    return false;
  }
  else {
    std::cout << "Hash of RCA certificate matches received hash." << std::endl;
  }

  // Verify signature.
  if (!VerifySignedData(*sd)) {
    std::cerr << "Signed data could not be verified." << std::endl;
    return false;
  }
  else {
    std::cout << "Signature verified succesfuly." << std::endl;
  }


  OCTET_STRING& unsecuredData = sd->tbsData->payload->data->content->choice.unsecuredData;
  ByteBuffer data(unsecuredData.buf,
                  unsecuredData.buf + unsecuredData.size);

  asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 {asn_DEF_EtsiTs102941Data};
  data102941.decode(data);

  ToBeSignedCrl& tbsCrl = data102941->content.choice.certificateRevocationList;

  ParseRcaCrl(tbsCrl);

  return true;
}

bool CertificateTrustListManager::GetEctl()
{
  if (!ectlTlmCert) {
    LoadEctlTlmCert();
  }

  security::HashedId8 ectlTlmCertDigest = CalculateCertificateDigest(*ectlTlmCert);
  std::string hash = HashedId8toString(ectlTlmCertDigest);
  std::string url = ectlUrlL0 + std::string("getectl/") + hash;
  std::cout << "Requesting ECTL from TLM (" << url << ")." << std::endl;
  ByteBuffer ectlBuf = RequestCtl(url);

  asn1::asn1c_oer_wrapper<TlmCertificateTrustListMessage_t> ectl {asn_DEF_TlmCertificateTrustListMessage};
  ectl.decode(ectlBuf);

  if (ectl->content->present != Ieee1609Dot2Content_PR_signedData) {
    std::cerr << "Invalid ECTL." << std::endl;
    return false;
  }

  SignedData* sd = ectl->content->choice.signedData;

  // Check if cert in signed data has same hash as RCA.
  security::HashedId8 certHash = GetSignerDigest(*sd);
  if (certHash != ectlTlmCertDigest) {
    std::cerr << "TLM certificate differs from saved ECTL TLM" << std::endl;
    return false;
  }
  else {
    std::cout << "Hash of TLM certificate matches received hash." << std::endl;
  }

  // Verify signature.
  if (!VerifySignedData(*sd)) {
    std::cerr << "Signed data could not be verified." << std::endl;
    return false;
  }
  else {
    std::cout << "Signature verified succesfuly." << std::endl;
  }

  OCTET_STRING& unsecuredData = sd->tbsData->payload->data->content->choice.unsecuredData;
  ByteBuffer data(unsecuredData.buf,
                  unsecuredData.buf + unsecuredData.size);

  asn1::asn1c_oer_wrapper<EtsiTs102941Data> data102941 {asn_DEF_EtsiTs102941Data};
  data102941.decode(data);

  CtlFormat_t& tbsCtl = data102941->content.choice.certificateTrustListTlm;

  ParseTlmCtl(tbsCtl);

  return true;
}

CertificateTrustListManager::RcaEntry CertificateTrustListManager::GetRca(const vanetza::security::HashedId8& rcaHash)
{
  auto rca = rcaList.find(rcaHash);
  if (rca == rcaList.end()) {
    std::cerr << "No RCA with hash in trust list." << std::endl;
  }

  return rca->second;
}
