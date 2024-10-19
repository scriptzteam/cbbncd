#pragma once

#include <list>
#include <memory>
#include <string>

#include "../core/types.h"

class TrafficBncSession;

class TrafficBncSessions {
public:
  TrafficBncSessions();
  virtual ~TrafficBncSessions();
  int activate(Core::AddressFamily pasvaddrfam, Core::AddressFamily portaddrfam, const std::string& host, int port, const std::string& sessiontag);
  void disconnect();
private:
  std::list<std::unique_ptr<TrafficBncSession>> tbncsessions;
};
