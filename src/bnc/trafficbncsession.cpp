#include "trafficbncsession.h"

#include "../globalcontext.h"
#include "../listenportmanager.h"
#include "../util.h"

#include "pasvlistener.h"
#include "pasvconn.h"
#include "portconn.h"

TrafficBncSession::TrafficBncSession(int id) : pasvlistener(new PasvListener(this)),
  pasvconn(new PasvConn(this)), portconn(new PortConn(this)), state(State::INACTIVE),
  id(id)
{
}

TrafficBncSession::~TrafficBncSession() {
}

int TrafficBncSession::activate(Core::AddressFamily pasvaddrfam, Core::AddressFamily portaddrfam, const std::string& host, int port, const std::string& sessiontag) {
  this->portaddrfam = portaddrfam;
  this->pasvaddrfam = pasvaddrfam;
  this->targethost = host;
  this->targetport = port;
  this->sessiontag = sessiontag + " #" + std::to_string(id);
  bool success = false;
  int bindport = -1;
  if (state == State::AWAITING_PASV) {
    global->getListenPortManager()->releasePort(pasvlistener->getListenPort());
  }
  while (!success) {
    bindport = global->getListenPortManager()->acquirePort();
    if (bindport == -1) {
      // exhausted
      return -1;
    }
    success = pasvlistener->listen(pasvaddrfam, bindport, sessiontag);
    if (!success) {
      global->getListenPortManager()->markPortUnavailable(bindport);
    }
  }
  global->log("[" + this->sessiontag + "] Listening for a traffic connection on " +
    (pasvaddrfam == Core::AddressFamily::IPV6 ? "IPv6 " : "") + "port " + std::to_string(bindport));
  state = State::AWAITING_PASV;
  return bindport;
}

void TrafficBncSession::disconnect() {
  pasvconn->disconnect();
  portconn->disconnect();
  pasvlistener->disconnect();
  if (state == State::AWAITING_PASV) {
    global->getListenPortManager()->releasePort(pasvlistener->getListenPort());
  }
  state = State::INACTIVE;
}

void TrafficBncSession::pasvConnected(int newsockid) {
  state = State::ACTIVE;
  pasvconn->activate(newsockid, sessiontag);
  global->log("[" + sessiontag + "] Traffic connection established from " +
    util::ipFormat(pasvaddrfam, pasvconn->getAddress()) + ":" + std::to_string(pasvconn->getPort()));
  portconn->activate(portaddrfam, targethost, targetport, sessiontag);
  global->log("[" + sessiontag + "] Opening traffic connection to " +
    util::ipFormat(portaddrfam, targethost) + ":" + std::to_string(targetport));
  global->getListenPortManager()->releasePort(pasvlistener->getListenPort());
}

void TrafficBncSession::portConnectFailure() {
  pasvconn->disconnect();
  state = State::INACTIVE;
}

void TrafficBncSession::portConnected() {
  pasvconn->startPolling();
  global->log("[" + sessiontag + "] Both traffic connections established. Traffic bouncing active: " +
    util::ipFormat(portaddrfam, targethost) + ":" + std::to_string(targetport) + " <-> " +
    util::ipFormat(pasvaddrfam, pasvconn->getAddress()) + ":" + std::to_string(pasvconn->getPort()));
}

void TrafficBncSession::pasvConnData(char* data, unsigned int len) {
  bool needspause = !portconn->sendData(data, len);
  if (needspause) {
    pasvconn->pause();
  }
}

void TrafficBncSession::portConnData(char* data, unsigned int len) {
  bool needspause = !pasvconn->sendData(data, len);
  if (needspause) {
    portconn->pause();
  }
}

void TrafficBncSession::pasvConnClosed() {
  portconn->disconnect();
  transferFinished();
}

void TrafficBncSession::portConnClosed() {
  pasvconn->disconnect();
  transferFinished();
}

void TrafficBncSession::transferFinished() {
  global->log("[" + sessiontag + "] Traffic connections closed. Transfer complete, traffic bounce session finished.");
  state = State::INACTIVE;
}

void TrafficBncSession::pasvConnSendComplete() {
  if (portconn->isPaused()) {
    portconn->resume();
  }
}

void TrafficBncSession::portConnSendComplete() {
  if (pasvconn->isPaused()) {
    pasvconn->resume();
  }
}

bool TrafficBncSession::isActive() const {
  return state != State::INACTIVE;
}

void TrafficBncSession::dropListener() {
  if (state == State::AWAITING_PASV) {
    pasvlistener->disconnect();
    global->getListenPortManager()->releasePort(pasvlistener->getListenPort());
    state = State::INACTIVE;
  }
}
