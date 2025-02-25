#include <vanetza/asn1/pki/EtsiTs103097Certificate.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/security/v2/persistence.hpp>

#include <iostream>

#include <boost/program_options.hpp>

#include "enrolment.h"
#include "helpers.h"

using namespace vanetza::security;
namespace po = boost::program_options;

int main(int argc, const char** argv)
{
  po::options_description options("Allowed options");
  options.add_options()
    ("ectl",      "Request European certificate trust list from EU TLM")
    ("ctl",       "Request certificate trust list from rca")
    ("cert", po::value<std::string>(), "  Path to root CA certificate")
    ("dc",   po::value<std::string>(), "  URL of root CA distribution centre")
    ("enrol",     "Send enrolment request to EA")
    ("id",       po::value<std::string>(), "  Canonical ID of ITS-S")
    ("canonkey", po::value<std::string>(), "  Keypair the ITS-S is registered with")
    ("authorize", "Send authorization request to AA")
    ("ec",     po::value<std::string>(), "  Enrolment credential of ITS-S")
    ("verkey", po::value<std::string>(), "  Verification key for signing request")
    ("full",      "Do complete process: RCA CTL, enrol, authorize")
    ("save,s", po::value<std::string>()->default_value("certs"), "Path where to save received certificates")
    ("help,h",    "Show this message and exit")
  ;

  po::positional_options_description positional_options;
  positional_options.add("interface", 1);

  po::variables_map vm;

  try {
    po::store(
      po::command_line_parser(argc, argv)
        .options(options)
        .positional(positional_options)
        .run(),
      vm
    );
    po::notify(vm);
  } catch (po::error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
    std::cerr << options << std::endl;
    return 1;
  }

  if (vm.count("help")) {
    std::cout << options << std::endl;
    return 0;
  }

  if (vm.count("ectl")) {
    CertificateTrustListManager ctlm;
    if (!ctlm.GetEctl())
      return 1;

    std::cout << "ECTL includes:" << std::endl;
    ctlm.PrintRca();

    return 0;
  }
  else if (vm.count("ctl")) {
    if (vm["cert"].empty() || vm["dc"].empty()) {
      std::cerr << "Need to specify path to Root CA certificate and URL of distribution centre." << std::endl;
      std::cerr << options << std::endl;
      return 1;
    }

    std::string rcaCertPath = vm["cert"].as<std::string>();
    std::string dcUrl = vm["dc"].as<std::string>();

    vanetza::security::v3::Certificate rcaCert;
    LoadCertificate(rcaCertPath, rcaCert);

    CertificateTrustListManager ctlm(rcaCert, dcUrl);

    vanetza::security::HashedId8 certHash = CalculateCertificateDigest(*rcaCert);
    if (!ctlm.GetCtl(certHash))
      return 1;

    std::cout << "CTL includes:" << std::endl;
    ctlm.PrintRca();

    return 0;
  }
  else if (vm.count("enrol")) {
    if (vm["cert"].empty() || vm["dc"].empty() || vm["canonkey"].empty() || vm["id"].empty()) {
      std::cerr << "Need to specify: Path to RCA cert, DC URL, ITS-S ID and path to ITS-S canonical key." << std::endl;
      std::cerr << options << std::endl;
      return 1;
    }

    std::string rcaCertPath = vm["cert"].as<std::string>();
    std::string dcUrl = vm["dc"].as<std::string>();
    std::string keyPath = vm["canonkey"].as<std::string>();
    std::string itsId = vm["id"].as<std::string>();

    vanetza::security::v3::Certificate rcaCert;
    LoadCertificate(rcaCertPath, rcaCert);

    CertificateTrustListManager ctlm(rcaCert, dcUrl);

    vanetza::security::HashedId8 certHash = CalculateCertificateDigest(*rcaCert);
    if (!ctlm.GetCtl(certHash))
      return 1;

    ecdsa256::KeyPair canonicalKeyPair = v2::load_private_key_from_file(keyPath);

    CertificateManager cm(itsId, canonicalKeyPair, ctlm.GetRca(certHash));
    if (!cm.RequestEc()) {
      std::cerr << "Enrolment failed." << std::endl;
      return 1;
    }
    cm.SaveVerificationKey("ECVerificationKey");
    cm.SaveEc("EnrolmentCredential");

    return 0;
  }
  else if (vm.count("authorize")) {
    if (vm["cert"].empty() || vm["dc"].empty() || vm["verkey"].empty() || vm["ec"].empty()) {
      std::cerr << "Need to specify: Path to RCA cert, DC URL, enrolment credential and path to ITS-S verification key." << std::endl;
      std::cerr << options << std::endl;
      return 1;
    }

    std::string rcaCertPath = vm["cert"].as<std::string>();
    std::string dcUrl = vm["dc"].as<std::string>();
    std::string keyPath = vm["verkey"].as<std::string>();
    std::string ecPath = vm["ec"].as<std::string>();

    vanetza::security::v3::Certificate rcaCert;
    LoadCertificate(rcaCertPath, rcaCert);

    CertificateTrustListManager ctlm(rcaCert, dcUrl);

    vanetza::security::HashedId8 certHash = CalculateCertificateDigest(*rcaCert);
    if (!ctlm.GetCtl(certHash))
      return 1;

    ecdsa256::KeyPair verKeyPair = v2::load_private_key_from_file(keyPath);

    CertificateManager cm("", verKeyPair, ctlm.GetRca(certHash));

    vanetza::security::v3::Certificate enrolmentCredential;
    LoadCertificate(ecPath, enrolmentCredential);
    cm.LoadEc(&*enrolmentCredential);
    if (!cm.RequestAt()) {
      std::cerr << "Authorization failed failed." << std::endl;
      return 1;
    }
    cm.SaveVerificationKey("ATVerificationKey");
    cm.SaveAt("AuthorizationTicket");

    return 0;
  }
  else if (vm.count("full")) {
    if (vm["cert"].empty() || vm["dc"].empty() || vm["canonkey"].empty() || vm["id"].empty()) {
      std::cerr << "Need to specify: Path to RCA cert, DC URL, ITS-S ID and path to ITS-S canonical key." << std::endl;
      std::cerr << options << std::endl;
      return 1;
    }

    std::string rcaCertPath = vm["cert"].as<std::string>();
    std::string dcUrl = vm["dc"].as<std::string>();
    std::string keyPath = vm["canonkey"].as<std::string>();
    std::string itsId = vm["id"].as<std::string>();

    vanetza::security::v3::Certificate rcaCert;
    LoadCertificate(rcaCertPath, rcaCert);

    CertificateTrustListManager ctlm(rcaCert, dcUrl);

    vanetza::security::HashedId8 certHash = CalculateCertificateDigest(*rcaCert);
    if (!ctlm.GetCtl(certHash))
      return 1;

    ecdsa256::KeyPair canonicalKeyPair = v2::load_private_key_from_file(keyPath);

    CertificateManager cm(itsId, canonicalKeyPair, ctlm.GetRca(certHash));
    if (!cm.RequestEc()) {
      std::cerr << "Enrolment failed." << std::endl;
      return 1;
    }
    cm.SaveVerificationKey("ECVerificationKey");
    cm.SaveEc("EnrolmentCredential");

    if (!cm.RequestAt()) {
      std::cerr << "Authorization failed failed." << std::endl;
      return 1;
    }
    cm.SaveVerificationKey("ATVerificationKey");
    cm.SaveAt("AuthorizationTicket");

    return 0;
  }

  return 0;
}
