#include "pasvlistener.h"

#include "../core/iomanager.h"

#include "../globalcontext.h"

#include "trafficbncsession.h"

PasvListener::PasvListener(TrafficBncSession* tbnc) : tbnc(tbnc), sockid(-1) {
}

bool PasvListener::listen(Core::AddressFamily addrfam, int port, const std::string& sessiontag) {
  disconnect();
  listenport = port;
  this->sessiontag = sessiontag;
  sockid = global->getIOManager()->registerTCPServerSocket(this, listenport, addrfam);
  if (sockid == -1) {
    failedlistenports.push_back(listenport);
  }
  return sockid != -1;
}

void PasvListener::disconnect() {
  if (sockid == -1) {
    return;
  }
  global->getIOManager()->closeSocket(sockid);
  sockid = -1;
}

void PasvListener::FDNew(int sockid, int newsockid) {
  tbnc->pasvConnected(newsockid);
  disconnect();
}

void PasvListener::FDFail(int sockid, const std::string& err) {
  if (!failedlistenports.empty()) {
    global->log("[" + sessiontag + "] Failed to bind on port " + std::to_string(failedlistenports.front()) + ": " + err);
    failedlistenports.pop_front();
  }
  else {
    global->log("[" + sessiontag + "] Failed to bind server socket: " + err);
  }
  sockid = -1;
}

int PasvListener::getListenPort() const {
  return listenport;
}
