#pragma once

#include <list>
#include <string>
#include <vector>

#include "core/types.h"

namespace util {

std::list<std::string> trim(const std::list<std::string>& in);
std::list<std::string> split(const std::string& in, const std::string& sep = " ");
std::vector<std::string> splitVec(const std::string& in, const std::string& sep = " ");
std::string ipFormat(Core::AddressFamily addrfam, const std::string addr);

}
