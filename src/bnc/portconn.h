#pragma once

#include <string>

#include "../core/eventreceiver.h"
#include "../core/types.h"

class TrafficBncSession;

class PortConn : private Core::EventReceiver {
public:
  PortConn(TrafficBncSession* tbnc);
  void activate(Core::AddressFamily addrfam, const std::string& host, int port, const std::string& sessiontag);
  bool sendData(char* data, unsigned int datalen);
  void disconnect();
  bool isPaused() const;
  void pause();
  void resume();
private:
  void FDConnected(int sockid) override;
  void FDData(int sockid, char* data, unsigned int datalen) override;
  void FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) override;
  void FDFail(int sockid, const std::string& err) override;
  void FDSendComplete(int sockid) override;
  TrafficBncSession* tbnc;
  int sockid;
  Core::AddressFamily addrfam;
  std::string host;
  int port;
  std::string sessiontag;
  bool paused;
};
