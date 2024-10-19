#pragma once

#include <list>
#include <string>
#include <vector>

#include "../core/eventreceiver.h"
#include "../core/types.h"

#include "../address.h"

class BncSessionClient;
class Ident;

enum class State {
  DISCONNECTED,
  IDENT,
  ESTABLISHED
};

class BncSession : private Core::EventReceiver {
public:
  BncSession(int listenport, bool ident, bool noidnt, bool traffic, bool nat, const std::vector<Address>& natips);
  bool active();
  void activate(int sockid, const Address& addr);
  void targetDisconnected();
  bool targetData(char* data, unsigned int datalen);
  void targetSendComplete();
  void ident(const std::string& ident);
  void negotiateTLS();
private:
  void FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) override;
  void FDData(int sockid, char* data, unsigned int datalen) override;
  void FDSendComplete(int sockid) override;
  void FDSSLSuccess(int sockid, const std::string& cipher) override;
  void sendQueuedData();
  BncSessionClient* sessionclient;
  Ident* identp;
  bool noidnt;
  State state;
  int listenport;
  Core::AddressFamily siteaddrfam;
  std::string sitehost;
  int siteport;
  int sockid;
  std::string srcaddr;
  bool nat;
  std::string natip4;
  std::string natip6;
  std::string sessiontag;
  bool paused;
  std::list<std::vector<char>> sendqueue;
  Core::AddressFamily srcaddrfam;
};
