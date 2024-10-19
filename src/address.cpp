#include "address.h"

#include "util.h"

namespace {

}

Address::Address() : addrfam(Core::AddressFamily::IPV4_IPV6), brackets(false), port(21) {

}

Address::Address(const std::string& host, int port, Core::AddressFamily addrfam, bool brackets) : addrfam(addrfam), brackets(brackets), host(host), port(port) {

}

std::string Address::toString(bool includeaddrfam) const {
  std::string addrstr;
  if (includeaddrfam) {
    if (addrfam == Core::AddressFamily::IPV4) {
      addrstr += "(4)";
    }
    else if (addrfam == Core::AddressFamily::IPV6) {
      addrstr += "(6)";
    }
  }
  if (brackets) {
    addrstr += "[";
  }
  addrstr += host;
  if (brackets) {
    addrstr += "]";
  }
  if (port != 21) {
    addrstr += ":" + std::to_string(port);
  }
  return addrstr;
}

bool Address::operator==(const Address& other) const {
  return addrfam == other.addrfam && brackets == other.brackets && host == other.host && port == other.port;
}

Address parseAddress(std::string address) {
  Address addr;
  addr.addrfam = Core::AddressFamily::IPV4_IPV6;
  addr.port = 21;
  addr.brackets = false;
  if (address.length() > 3) {
    std::string prefix = address.substr(0, 3);
    if (prefix == "(4)") {
      addr.addrfam = Core::AddressFamily::IPV4;
      address = address.substr(3);
    }
    else if (prefix == "(6)") {
      addr.addrfam = Core::AddressFamily::IPV6;
      address = address.substr(3);
    }
  }
  int colons = 0;
  if (addr.addrfam == Core::AddressFamily::IPV4_IPV6) {
    bool canbeipv4 = true;
    for (size_t i = 0; i < address.length(); ++i) {
      if (i == 0 && address[i] == '0' && address.length() >= 2 && address[i+1] == 'x') {
        ++i;
        continue;
      }
      if (address[i] == ':') {
        ++colons;
        if (colons >= 2) {
          canbeipv4 = false;
        }
      }
      if (canbeipv4 && !((address[i] >= '0' && address[i] <= '9') || address[i] == '.' || address[i] == ':')) {
        canbeipv4 = false;
      }
    }
    if (colons >= 2) {
      addr.addrfam = Core::AddressFamily::IPV6;
    }
    else if (canbeipv4) {
      addr.addrfam = Core::AddressFamily::IPV4;
    }
  }

  size_t portpos = std::string::npos;
  if (!address.empty() && address[0] == '[') {
    size_t bracketendpos = address.find("]");
    if (bracketendpos != std::string::npos) {
      addr.brackets = true;
      addr.host = address.substr(1, bracketendpos - 1);
      portpos = address.find(":", bracketendpos);
    }
  }
  if (!addr.brackets) {
    if (addr.addrfam != Core::AddressFamily::IPV6) {
      portpos = address.find(":");
    }
    if (portpos != std::string::npos) {
      addr.host = address.substr(0, portpos);
    }
    else {
      addr.host = address;
    }
  }
  if (portpos != std::string::npos) {
    try {
      addr.port = std::stoi(address.substr(portpos + 1));
    }
    catch (std::exception&) {
    }
  }
  if (addr.port == 21) {
    addr.brackets = false;
  }
  return addr;
}

std::list<Address> parseAddresses(std::string addrstr) {
  std::list<Address> addresses;
  size_t pos;
  while ((pos = addrstr.find(";")) != std::string::npos) addrstr[pos] = ' ';
  while ((pos = addrstr.find(",")) != std::string::npos) addrstr[pos] = ' ';
  while (true) {
    size_t pos = addrstr.find("  ");
    if (pos == std::string::npos) {
      break;
    }
    addrstr.erase(pos, 1);
  }
  std::list<std::string> addrlist = util::trim(util::split(addrstr));
  for (const std::string& address : addrlist) {
    addresses.push_back(parseAddress(address));
  }
  return addresses;
}
