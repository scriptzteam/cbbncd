#pragma once

#include <list>
#include <memory>
#include <vector>

#include "../core/eventreceiver.h"
#include "../core/types.h"

#include "../ftp/commandparser.h"
#include "../ftp/responseparser.h"

enum class TLSState {
  NONE,
  QUERY,
  IN_PROGRESS,
  ACTIVE
};

enum class ResponseCatch {
  NONE,
  AUTH_TLS,
  PASV,
  EPSV,
  PORT, // only used on port exhaustion
  EPRT  // only used on port exhaustion
};

enum class OriginCatch {
  NONE,
  PASV,
  EPSV_1,
  EPSV_2,
  PORT
};

class BncSession;
class TrafficBncSessions;

class BncSessionClient : private Core::EventReceiver {
public:
  BncSessionClient(BncSession* parentsession, bool traffic, bool noidnt, bool nat);
  ~BncSessionClient();
  void activate(const std::string& sessiontag, Core::AddressFamily clientaddrfam, const std::string& clientaddr, Core::AddressFamily siteaddrfam, const std::string& sitehost, int siteport, const std::string& rewriteaddr4, const std::string& rewriteaddr6);
  void ident(const std::string& ident);
  void disconnect();
  bool sendData(const char* data, unsigned int datalen);
  void sendComplete();
  void parentTLSSuccess(const std::string& cipher);
private:
  void FDConnected(int sockid) override;
  void FDData(int sockid, char* data, unsigned int datalen) override;
  void FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) override;
  void FDFail(int sockid, const std::string& err) override;
  void FDSendComplete(int sockid) override;
  void FDSSLSuccess(int sockid, const std::string& cipher) override;
  void checkSendIdent();
  void checkMitm();
  int sockid;
  BncSession* session;
  std::string identstr;
  bool identreceived;
  std::string sessiontag;
  bool paused;
  bool connected;
  FTPCommandParser commandparser;
  FTPResponseParser responseparser;
  ResponseCatch responsecatch;
  OriginCatch origincatch;
  TLSState tlsstate;
  std::string parentcipher;
  std::string cipher;
  std::unique_ptr<TrafficBncSessions> tbncsessions;
  std::string rewriteaddr4;
  std::string rewriteaddr6;
  bool traffic;
  std::string sitehost;
  Core::AddressFamily clientaddrfam;
  Core::AddressFamily siteaddrfam;
  std::string clientaddr;
  std::string siterewriteaddr;
  bool noidnt;
  bool nat;
};
