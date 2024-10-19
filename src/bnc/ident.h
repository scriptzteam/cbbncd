#pragma once

#include <string>

#include "../core/eventreceiver.h"
#include "../core/types.h"

class BncSession;

class Ident : private Core::EventReceiver {
public:
  Ident(BncSession* bncsession);
  void activate(const std::string& sessiontag, Core::AddressFamily sourceaddrfam, const std::string& sourcehost, int sourceport, int targetport);
  void close();
private:
  void FDConnected(int sockid) override;
  void FDData(int sockid, char* buf, unsigned int buflen) override;
  void FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) override;
  void FDFail(int sockid, const std::string& err) override;
  void tick(int);
  void deactivate();
  void noIdent();
  BncSession* bncsession;
  bool active;
  int sockid;
  int sourceport;
  int targetport;
  std::string sessiontag;
};
