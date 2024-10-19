#include "pasvstring.h"

namespace {

std::string addressFamilyToString(const Core::AddressFamily& addrfam) {
  switch(addrfam) {
    case Core::AddressFamily::NONE:
      return "";
    case Core::AddressFamily::IPV4:
      return "1";
    case Core::AddressFamily::IPV6:
      return "2";
    case Core::AddressFamily::IPV4_IPV6:
      return "?";
  }
  return "<unknown address family type " + std::to_string(static_cast<int>(addrfam)) + ">";
}

Core::AddressFamily stringToAddressFamily(const std::string& str) {
  if (str == "1") {
    return Core::AddressFamily::IPV4;
  }
  if (str == "2") {
    return Core::AddressFamily::IPV6;
  }
  return Core::AddressFamily::NONE;
}

}

bool fromPASVString(const std::string& pasv, std::string& addr, int& port) {
  addr = pasv;
  size_t sep1 = addr.find(",");
  if (sep1 == std::string::npos) {
    return false;
  }
  size_t sep2 = addr.find(",", sep1 + 1);
  if (sep2 == std::string::npos) {
    return false;
  }
  size_t sep3 = addr.find(",", sep2 + 1);
  if (sep3 == std::string::npos) {
    return false;
  }
  size_t sep4 = addr.find(",", sep3 + 1);
  if (sep4 == std::string::npos) {
    return false;
  }
  size_t sep5 = addr.find(",", sep4 + 1);
  if (sep5 == std::string::npos) {
    return false;
  }
  addr[sep1] = '.';
  addr[sep2] = '.';
  addr[sep3] = '.';
  addr = addr.substr(0, sep4);
  int major = std::stoi(pasv.substr(sep4 + 1, sep5 - sep4 + 1));
  int minor = std::stoi(pasv.substr(sep5 + 1));
  port = major * 256 + minor;
  return true;
}

std::string toPASVString(const std::string& addr, int port) {
  std::string pasv = addr;
  size_t pos;
  while ((pos = pasv.find(".")) != std::string::npos) {
    pasv[pos] = ',';
  }
  int portfirst = port / 256;
  int portsecond = port % 256;
  return pasv + "," + std::to_string(portfirst) + "," + std::to_string(portsecond);
}

bool fromExtendedPASVString(const std::string& epsv, Core::AddressFamily& addrfam, std::string& addr, int& port) {
  size_t sep1 = epsv.find('|');
  if (sep1 == std::string::npos) {
    return false;
  }
  size_t sep2 = epsv.find('|', sep1 + 1);
  if (sep2 == std::string::npos) {
    return false;
  }
  size_t sep3 = epsv.find('|', sep2 + 1);
  if (sep3 == std::string::npos) {
    return false;
  }
  size_t sep4 = epsv.find('|', sep3 + 1);
  if (sep4 == std::string::npos) {
    return false;
  }
  addrfam = stringToAddressFamily(epsv.substr(sep1 + 1, sep2 - sep1 - 1));
  addr = epsv.substr(sep2 + 1, sep3 - sep2 - 1);
  port = std::stol(epsv.substr(sep3 + 1, sep4 - sep3 - 1));
  return true;
}

std::string toExtendedPASVString(Core::AddressFamily addrfam, const std::string& addr, int port) {
  return "|" + addressFamilyToString(addrfam) + "|" + addr + "|" + std::to_string(port) + "|";
}

std::string toExtendedPASVString(int port) {
  return toExtendedPASVString(Core::AddressFamily::NONE, "", port);
}
