#include "bnc.h"

#include <cstdlib>

#include "../core/iomanager.h"

#include "../globalcontext.h"

#include "bncsession.h"

Bnc::Bnc(int listenport, const std::list<Address>& siteaddrs, bool ident, bool noidnt,
  bool traffic, bool nat, const std::list<Address>& natips, int pasvportfirst,
  int pasvportlast) : listenport(listenport),
  siteaddrs(siteaddrs.begin(), siteaddrs.end()), ident(ident), noidnt(noidnt), traffic(traffic),
  nat(nat), natips(natips.begin(), natips.end()), pasvportfirst(pasvportfirst), pasvportlast(pasvportlast), nextsiteaddr(0)
{
  global->getIOManager()->registerTCPServerSocket(this, listenport, Core::AddressFamily::IPV4);
  global->getIOManager()->registerTCPServerSocket(this, listenport, Core::AddressFamily::IPV6);
}

void Bnc::FDNew(int sockid, int newsockid) {
  const Address& siteaddr = siteaddrs.at(nextsiteaddr);
  nextsiteaddr = (nextsiteaddr + 1) % siteaddrs.size();
  std::list<BncSession*>::iterator it;
  for (it = sessions.begin(); it != sessions.end(); it++) {
    if (!(*it)->active()) {
      (*it)->activate(newsockid, siteaddr);
      return;
    }
  }
  BncSession* session = new BncSession(listenport, ident, noidnt, traffic, nat, natips);
  session->activate(newsockid, siteaddr);
  sessions.push_back(session);
}

void Bnc::FDFail(int sockid, const std::string& err) {
  global->log("Error: failed to bind on port " + std::to_string(listenport) + ": " + err);
  exit(1);
}
