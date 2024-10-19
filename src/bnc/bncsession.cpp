#include "bncsession.h"

#include <sstream>

#include "../core/iomanager.h"

#include "../globalcontext.h"
#include "../util.h"

#include "bncsessionclient.h"
#include "ident.h"

namespace {

std::string colonReplace(const std::string& in) {
  std::string out;
  for (size_t i = 0; i < in.length(); ++i) {
    if (in[i] == ':') {
      out += "\\x3A";
    }
    else {
      out += in[i];
    }
  }
  return out;
}

}

BncSession::BncSession(int listenport, bool ident, bool noidnt, bool traffic, bool nat, const std::vector<Address>& natips) :
  sessionclient(new BncSessionClient(this, traffic, noidnt, nat)),
  identp((ident && !noidnt) ? new Ident(this) : nullptr),
  noidnt(noidnt),
  state(State::DISCONNECTED),
  listenport(listenport),
  sockid(-1),
  nat(nat),
  paused(false)
{
  for (const Address& addr : natips) {
    if (addr.addrfam == Core::AddressFamily::IPV6) {
      natip6 = addr.host;
    }
    else if (addr.addrfam == Core::AddressFamily::IPV4) {
      natip4 = addr.host;
    }
  }
}

bool BncSession::active() {
  return state != State::DISCONNECTED;
}

void BncSession::activate(int sockid, const Address& addr) {
  this->sockid = sockid;
  siteaddrfam = addr.addrfam;
  sitehost = addr.host;
  siteport = addr.port;
  paused = false;
  global->getIOManager()->registerTCPServerClientSocket(this, sockid);
  srcaddr = global->getIOManager()->getSocketAddress(sockid);
  std::string rewriteaddr4;
  std::string rewriteaddr6;
  if (nat) {
    rewriteaddr4 = natip4;
    rewriteaddr6 = natip6;
  }
  if (!nat || rewriteaddr4.empty()) {
    Core::StringResult res = global->getIOManager()->getInterfaceAddress4(sockid);
    if (res.success) {
      rewriteaddr4 = res.result;
    }
  }
  if (!nat || rewriteaddr6.empty()) {
    Core::StringResult res = global->getIOManager()->getInterfaceAddress6(sockid);
    if (res.success) {
      rewriteaddr6 = res.result;
    }
  }
  srcaddrfam = global->getIOManager()->getAddressFamily(sockid);
  int srcport = global->getIOManager()->getSocketPort(sockid);
  sessiontag = util::ipFormat(srcaddrfam, srcaddr) + ":" + std::to_string(srcport);
  global->log("[" + sessiontag + "] New client connection");
  sessionclient->activate(sessiontag, srcaddrfam, srcaddr, siteaddrfam, sitehost, siteport, rewriteaddr4, rewriteaddr6);
  if (identp != nullptr) {
    state = State::IDENT;
    identp->activate(sessiontag, srcaddrfam, srcaddr, srcport, listenport);
  }
  else {
    state = State::ESTABLISHED;
    if (!noidnt) {
      std::string nocolonsrcaddr;
      for (size_t i = 0; i < srcaddr.length(); ++i) {
        if (srcaddr[i] == ':') {
          nocolonsrcaddr += "\x3A";
        }
        else {
          nocolonsrcaddr += srcaddr[i];
        }
      }
      sessionclient->ident("*@" + srcaddr + ":" + colonReplace(srcaddr));
    }
  }
}

void BncSession::ident(const std::string& ident) {
  if (state == State::IDENT) {
    state = State::ESTABLISHED;
    sessionclient->ident(ident + '@' + srcaddr + ":" + colonReplace(srcaddr));
    sendQueuedData();
  }
}

void BncSession::sendQueuedData() {
  while (!sendqueue.empty() && !paused) {
    const std::vector<char>& data = sendqueue.front();
    bool needspause = !sessionclient->sendData(const_cast<char*>(data.data()), data.size());
    sendqueue.pop_front();
    if (needspause) {
      if (!paused) {
        global->getIOManager()->pause(sockid);
        paused = true;
      }
      break;
    }
  }
}

void BncSession::FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) {
  if (state == State::IDENT) {
    identp->close();
  }
  global->log("[" + sessiontag + "] Client closed the connection. Disconnecting server. Session finished.");
  sessionclient->disconnect();
  sendqueue.clear();
  state = State::DISCONNECTED;
}

void BncSession::FDData(int sockid, char* data, unsigned int datalen) {
  if (state == State::IDENT) {
    sendqueue.emplace_back(data, data + datalen);
  }
  else if (state == State::ESTABLISHED) {
    if (!sessionclient->sendData(data, datalen) && !paused) {
      global->getIOManager()->pause(sockid);
      paused = true;
    }
  }
}

void BncSession::targetSendComplete() {
  if (paused) {
    global->getIOManager()->resume(sockid);
    paused = false;
    sendQueuedData();
  }
}

void BncSession::FDSendComplete(int sockid) {
  sessionclient->sendComplete();
}

void BncSession::FDSSLSuccess(int sockid, const std::string& cipher) {
  sessionclient->parentTLSSuccess(cipher);
}

void BncSession::targetDisconnected() {
  if (state == State::IDENT) {
    identp->close();
  }
  global->getIOManager()->closeSocket(sockid);
  sendqueue.clear();
  state = State::DISCONNECTED;
}

bool BncSession::targetData(char* data, unsigned int datalen) {
  return global->getIOManager()->sendData(sockid, data, datalen);
}

void BncSession::negotiateTLS() {
  global->getIOManager()->negotiateSSLAccept(sockid);
}
