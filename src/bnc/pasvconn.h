#pragma once

#include <string>

#include "../core/eventreceiver.h"

class TrafficBncSession;

class PasvConn : private Core::EventReceiver {
public:
  PasvConn(TrafficBncSession* tbnc);
  void activate(int sockid, const std::string& sessiontag);
  void startPolling();
  bool sendData(char* data, unsigned int datalen);
  void disconnect();
  std::string getAddress() const;
  int getPort() const;
  bool isPaused() const;
  void pause();
  void resume();
private:
  void FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) override;
  void FDData(int sockid, char* data, unsigned int datalen) override;
  void FDSendComplete(int sockid) override;
  TrafficBncSession* tbnc;
  int sockid;
  std::string addr;
  int port;
  std::string sessiontag;
  bool paused;
};
