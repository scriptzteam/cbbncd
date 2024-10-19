#include "pasvconn.h"

#include "../core/iomanager.h"
#include "../globalcontext.h"

#include "trafficbncsession.h"

PasvConn::PasvConn(TrafficBncSession* tbnc) : tbnc(tbnc), sockid(-1), port(-1) {
}

void PasvConn::activate(int sockid, const std::string& sessiontag) {
  this->sockid = sockid;
  this->sessiontag = sessiontag;
  paused = false;
  global->getIOManager()->registerTCPServerClientSocket(this, sockid, false);
  addr = global->getIOManager()->getSocketAddress(sockid);
  port = global->getIOManager()->getSocketPort(sockid);
}

void PasvConn::startPolling() {
  global->getIOManager()->resume(sockid);
}

bool PasvConn::sendData(char* data, unsigned int datalen) {
  return global->getIOManager()->sendData(sockid, data, datalen);
}

void PasvConn::FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) {
  if (this->sockid == -1 || this->sockid != sockid) {
    return;
  }
  sockid = -1;
  tbnc->pasvConnClosed();
}

void PasvConn::FDData(int sockid, char* data, unsigned int datalen) {
  tbnc->pasvConnData(data, datalen);
}

void PasvConn::FDSendComplete(int sockid) {
  tbnc->pasvConnSendComplete();
}

void PasvConn::disconnect() {
  if (sockid == -1) {
    return;
  }
  global->getIOManager()->closeSocket(sockid);
  sockid = -1;
}

std::string PasvConn::getAddress() const {
  return addr;
}

int PasvConn::getPort() const {
  return port;
}

bool PasvConn::isPaused() const {
  return paused;
}

void PasvConn::pause() {
  if (!paused) {
    global->getIOManager()->pause(sockid);
    paused = true;
  }
}

void PasvConn::resume() {
  if (paused) {
    global->getIOManager()->resume(sockid);
    paused = false;
  }
}
