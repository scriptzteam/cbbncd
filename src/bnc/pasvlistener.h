#pragma once

#include <list>
#include <string>

#include "../core/eventreceiver.h"
#include "../core/types.h"

class TrafficBncSession;

class PasvListener : private Core::EventReceiver {
public:
  PasvListener(TrafficBncSession* tbnc);
  bool listen(Core::AddressFamily addrfam, int port, const std::string& sessiontag);
  int getListenPort() const;
  void disconnect();
private:
  void FDNew(int sockid, int newsockid) override;
  void FDFail(int sockid, const std::string& error) override;
  TrafficBncSession* tbnc;
  int listenport;
  int sockid;
  std::string sessiontag;
  std::list<int> failedlistenports;
};
