#pragma once

#include <list>
#include <string>
#include <vector>

#include "../core/eventreceiver.h"
#include "../core/types.h"

#include "../address.h"

class BncSession;

class Bnc : private Core::EventReceiver {
public:
  Bnc(int listenport, const std::list<Address>& siteaddrs, bool ident, bool noidnt, bool traffic, bool nat, const std::list<Address>& natips, int pasvportfirst, int pasvportlast);
private:
  void FDNew(int sockid, int newsockid) override;
  void FDFail(int sockid, const std::string& error) override;
  std::list<BncSession*> sessions;
  int listenport;
  std::vector<Address> siteaddrs;
  Core::AddressFamily addrfam;
  std::string host;
  int port;
  bool ident;
  bool noidnt;
  bool traffic;
  bool nat;
  std::vector<Address> natips;
  int pasvportfirst;
  int pasvportlast;
  int nextsiteaddr;
};
