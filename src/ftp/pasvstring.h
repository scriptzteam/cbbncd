#pragma once

#include <string>

#include "../core/types.h"

bool fromPASVString(const std::string& pasv, std::string& addr, int& port);
std::string toPASVString(const std::string& addr, int port);
bool fromExtendedPASVString(const std::string& epsv, Core::AddressFamily& addrfam, std::string& addr, int& port);
std::string toExtendedPASVString(Core::AddressFamily addrfam, const std::string& addr, int port);
std::string toExtendedPASVString(int port);
