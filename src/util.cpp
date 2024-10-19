#include "util.h"

namespace util {

std::list<std::string> trim(const std::list<std::string>& in) {
  if (!in.empty() && !in.front().empty() && !in.back().empty()) {
    return in;
  }
  std::list<std::string> out = in;
  if (!out.empty() && out.front().empty()) {
    out.pop_front();
  }
  if (!out.empty() && out.back().empty()) {
    out.pop_back();
  }
  return out;
}

std::list<std::string> split(const std::string& in, const std::string& sep) {
  std::list<std::string> out;
  size_t start = 0;
  size_t end;
  size_t seplength = sep.length();
  while ((end = in.find(sep, start)) != std::string::npos) {
    out.push_back(in.substr(start, end - start));
    start = end + seplength;
  }
  out.push_back(in.substr(start));
  return out;
}

std::vector<std::string> splitVec(const std::string& in, const std::string& sep) {
  std::vector<std::string> out;
  size_t start = 0;
  size_t end;
  size_t seplength = sep.length();
  while ((end = in.find(sep, start)) != std::string::npos) {
    out.push_back(in.substr(start, end - start));
    start = end + seplength;
  }
  out.push_back(in.substr(start));
  return out;
}

std::string ipFormat(Core::AddressFamily addrfam, const std::string addr) {
  return addrfam == Core::AddressFamily::IPV6 ? "[" + addr + "]" : addr;
}

}
