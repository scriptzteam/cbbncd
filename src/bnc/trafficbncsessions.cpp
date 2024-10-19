#include "trafficbncsessions.h"

#include "trafficbncsession.h"

TrafficBncSessions::TrafficBncSessions() {
}

TrafficBncSessions::~TrafficBncSessions() {
}

int TrafficBncSessions::activate(Core::AddressFamily pasvaddrfam, Core::AddressFamily portaddrfam, const std::string& host, int port, const std::string& sessiontag) {
  const std::unique_ptr<TrafficBncSession>* targetsession = nullptr;
  for (const std::unique_ptr<TrafficBncSession>& session : tbncsessions) {
    session->dropListener();
    if (!session->isActive() && !targetsession) {
      targetsession = &session;
    }
  }
  if (!targetsession) {
    tbncsessions.emplace_back(new TrafficBncSession(tbncsessions.size()));
    targetsession = &tbncsessions.back();
  }
  return (*targetsession)->activate(pasvaddrfam, portaddrfam, host, port, sessiontag);
}

void TrafficBncSessions::disconnect() {
  for (const std::unique_ptr<TrafficBncSession>& session : tbncsessions) {
    session->disconnect();
  }
}
