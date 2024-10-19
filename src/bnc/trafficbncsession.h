#pragma once

#include <memory>

#include "../core/types.h"

class PasvListener;
class PasvConn;
class PortConn;

class TrafficBncSession {
public:
  TrafficBncSession(int id);
  ~TrafficBncSession();
  bool isActive() const;
  int activate(Core::AddressFamily pasvaddrfam, Core::AddressFamily portaddrfam, const std::string& host, int port, const std::string& sessiontag);
  void disconnect();
  void dropListener();
  void pasvConnected(int newsockid);
  void portConnectFailure();
  void portConnected();
  void pasvConnData(char* data, int unsigned len);
  void portConnData(char* data, int unsigned len);
  void pasvConnClosed();
  void portConnClosed();
  void pasvConnSendComplete();
  void portConnSendComplete();
private:
  enum class State {
    ACTIVE,
    AWAITING_PASV,
    INACTIVE
  };
  void transferFinished();
  std::unique_ptr<PasvListener> pasvlistener;
  std::unique_ptr<PasvConn> pasvconn;
  std::unique_ptr<PortConn> portconn;
  State state;
  std::string targethost;
  int targetport;
  std::string sessiontag;
  Core::AddressFamily portaddrfam;
  Core::AddressFamily pasvaddrfam;
  int id;
};
