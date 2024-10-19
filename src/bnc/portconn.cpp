#include "portconn.h"

#include "../globalcontext.h"
#include "../core/iomanager.h"

#include "trafficbncsession.h"

PortConn::PortConn(TrafficBncSession* tbnc) : tbnc(tbnc), sockid(-1) {
}

void PortConn::activate(Core::AddressFamily addrfam, const std::string& host, int port, const std::string& sessiontag) {
  this->addrfam = addrfam;
  this->host = host;
  this->port = port;
  this->sessiontag = sessiontag;
  paused = false;
  bool resolving;
  sockid = global->getIOManager()->registerTCPClientSocket(this, host, port, resolving, addrfam);
}

bool PortConn::sendData(char* data, unsigned int datalen) {
  return global->getIOManager()->sendData(sockid, data, datalen);
}

void PortConn::disconnect() {
  if (sockid == -1) {
    return;
  }
  global->getIOManager()->closeSocket(sockid);
  sockid = -1;
}

void PortConn::FDConnected(int sockid) {
  tbnc->portConnected();
}

void PortConn::FDData(int sockid, char* data, unsigned int datalen) {
  tbnc->portConnData(data, datalen);
}

void PortConn::FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) {
  if (this->sockid == -1 || this->sockid != sockid) {
    return;
  }
  this->sockid = -1;
  tbnc->portConnClosed();
}

void PortConn::FDFail(int sockid, const std::string& err) {
  global->log("Failed to connect to " + (addrfam == Core::AddressFamily::IPV4 ? host : "[" + host + "]")
    + ":" + std::to_string(port) + ": " + err);
  tbnc->portConnectFailure();
}

void PortConn::FDSendComplete(int sockid) {
  tbnc->portConnSendComplete();
}

bool PortConn::isPaused() const {
  return paused;
}

void PortConn::pause() {
  if (!paused) {
    global->getIOManager()->pause(sockid);
    paused = true;
  }
}

void PortConn::resume() {
  if (paused) {
    global->getIOManager()->resume(sockid);
    paused = false;
  }
}
