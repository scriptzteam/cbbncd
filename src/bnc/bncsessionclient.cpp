#include "bncsessionclient.h"

#include <cassert>

#include "../core/iomanager.h"

#include "../globalcontext.h"

#include "bncsession.h"
#include "trafficbncsessions.h"
#include "../util.h"

#include "../ftp/pasvstring.h"

namespace {

const std::string exhaustedresponse = "502 cbbncd: passive port range exhausted.\r\n";

}

BncSessionClient::BncSessionClient(BncSession * parentsession, bool traffic, bool noidnt, bool nat) :
  session(parentsession), paused(false), connected(false),
  tlsstate(TLSState::NONE), traffic(traffic), noidnt(noidnt), nat(nat)
{
  if (traffic) {
    tbncsessions = std::unique_ptr<TrafficBncSessions>(new TrafficBncSessions());
  }
}

BncSessionClient::~BncSessionClient() {
}

void BncSessionClient::activate(const std::string& sessiontag, Core::AddressFamily clientaddrfam, const std::string& clientaddr,
  Core::AddressFamily siteaddrfam, const std::string& sitehost, int siteport, const std::string& rewriteaddr4, const std::string& rewriteaddr6)
{
  this->sessiontag = sessiontag;
  this->rewriteaddr4 = rewriteaddr4;
  this->rewriteaddr6 = rewriteaddr6;
  this->clientaddrfam = clientaddrfam;
  this->siteaddrfam = siteaddrfam;
  this->sitehost = sitehost;
  this->clientaddr = clientaddr;
  identreceived = false;
  paused = false;
  connected = false;
  tlsstate = TLSState::NONE;
  commandparser.reset();
  responseparser.reset();
  responsecatch = ResponseCatch::NONE;
  origincatch = OriginCatch::NONE;
  global->log("[" + sessiontag + "] Connecting to server: " + util::ipFormat(siteaddrfam, sitehost) + ":" + std::to_string(siteport));
  bool resolving;
  sockid = global->getIOManager()->registerTCPClientSocket(this, sitehost, siteport, resolving, siteaddrfam);
}

void BncSessionClient::ident(const std::string& ident) {
  assert (!noidnt);
  this->identstr = ident;
  identreceived = true;
  checkSendIdent();
}

void BncSessionClient::disconnect() {
  connected = false;
  global->getIOManager()->closeSocket(sockid);
  if (tbncsessions) {
    tbncsessions->disconnect();
  }
}

void BncSessionClient::FDConnected(int sockid) {
  connected = true;
  global->log("[" + sessiontag + "] Server connection established.");
  if (noidnt) {
    global->log("[" + sessiontag + "] Control channel forwarding enabled.");
  }
  else {
    checkSendIdent();
  }
  siteaddrfam = global->getIOManager()->getAddressFamily(sockid);
  if (nat) {
    if (siteaddrfam == Core::AddressFamily::IPV4) {
      siterewriteaddr = rewriteaddr4;
    }
    if (siteaddrfam == Core::AddressFamily::IPV6) {
      siterewriteaddr = rewriteaddr6;
    }
  }
  else {
    siterewriteaddr = global->getIOManager()->getInterfaceAddress(sockid);
  }
}

void BncSessionClient::checkSendIdent() {
  if (identreceived && connected) {
    std::string identstring = "IDNT " + identstr;
    global->log("[" + sessiontag + "] Sending: " + identstring);
    global->log("[" + sessiontag + "] Control channel bouncing enabled.");
    global->getIOManager()->sendData(sockid, identstring + "\r\n");
  }
}

void BncSessionClient::FDDisconnected(int sockid, Core::DisconnectType reason, const std::string& details) {
  global->log("[" + sessiontag + "] Server closed the connection. Disconnecting client. Session finished.");
  connected = false;
  session->targetDisconnected();
  if (tbncsessions) {
    tbncsessions->disconnect();
  }
}

void BncSessionClient::FDFail(int sockid, const std::string& err) {
  global->log("[" + sessiontag + "] Server connection failed: " + err);
  global->log("[" + sessiontag + "] Disconnecting client. Session finished.");
  session->targetDisconnected();
}

void BncSessionClient::FDData(int sockid, char* data, unsigned int datalen) {
  if (!traffic || responsecatch == ResponseCatch::NONE) {
    bool pause = !session->targetData(data, datalen) && !paused;
    if (pause) {
      global->getIOManager()->pause(sockid);
      paused = true;
    }
    return;
  }
  if (responseparser.parse(data, datalen)) {
    bool starttls = false;
    char* respdata = responseparser.getResponseData();
    std::string modifiedresponse;
    unsigned int respdatalen = responseparser.getResponseDataLength();
    switch (responsecatch) {
      case ResponseCatch::NONE:
        break;
      case ResponseCatch::AUTH_TLS:
        if (responseparser.getResponseCode() == 234) {
          tlsstate = TLSState::IN_PROGRESS;
          starttls = true;
        }
        break;
      case ResponseCatch::PASV:
        if (responseparser.getResponseCode() == 227) {
          std::string response = std::string(respdata, respdatalen);
          size_t start = response.find('(') + 1;
          size_t end = response.find(')');
          std::string pasvstring = response.substr(start, end - start);
          int count = 0;
          for (unsigned int i = 0; i < pasvstring.length(); i++) {
            if (pasvstring[i] == ',') count++;
          }
          if (count == 2 && pasvstring.substr(0, 2) == "1,") {
            std::string connaddr = sitehost;
            for (unsigned int i = 0; i < connaddr.length(); i++) {
              if (connaddr[i] == '.') connaddr[i] = ',';
            }
            pasvstring = connaddr + "," + pasvstring.substr(2);
          }
          std::string addr;
          int port;
          if (fromPASVString(pasvstring, addr, port)) {
            global->log("[" + sessiontag + "] Caught PASV response, preparing traffic bounce session");
            int boundport = tbncsessions->activate(Core::AddressFamily::IPV4, Core::AddressFamily::IPV4, addr, port, sessiontag);
            if (boundport != -1) {
              modifiedresponse = response.substr(0, start) + toPASVString(rewriteaddr4, boundport) + response.substr(end);
              global->log("[" + sessiontag + "] Rewriting PASV string " + addr + ":" + std::to_string(port) +
                " -> " + rewriteaddr4 + ":" + std::to_string(boundport));
              break;
            }
            global->log("[" + sessiontag + "] Passive port range exhausted. Please make more ports available.");
            modifiedresponse = exhaustedresponse;
            break;
          }
          else {
            global->log("[" + sessiontag + "] Caught malformatted PASV response, ignoring. (" +response + ")");
          }
        }
        break;
      case ResponseCatch::EPSV:
        if (responseparser.getResponseCode() == 229) {
          std::string response = std::string(respdata, respdatalen);
          size_t start = response.find('(') + 1;
          size_t end = response.find(')');
          std::string epsvstring = response.substr(start, end - start);
          Core::AddressFamily addrfam;
          std::string addr;
          int port;
          if (fromExtendedPASVString(epsvstring, addrfam, addr, port)) {
            std::string useaddr = addr;
            if (addr.empty()) {
              addrfam = siteaddrfam;
              useaddr = sitehost;
            }
            Core::AddressFamily originaddrfam = addrfam;
            if (origincatch == OriginCatch::EPSV_1 || origincatch == OriginCatch::PASV) {
              originaddrfam = Core::AddressFamily::IPV4;
            }
            else if (origincatch == OriginCatch::EPSV_2) {
              originaddrfam = Core::AddressFamily::IPV6;
            }
            std::string rewriteaddr = originaddrfam == Core::AddressFamily::IPV4 ? rewriteaddr4 : rewriteaddr6;
            global->log("[" + sessiontag + "] Caught EPSV response, preparing traffic bounce session");
            int boundport = tbncsessions->activate(originaddrfam, addrfam, useaddr, port, sessiontag);
            if (boundport != -1) {
              if (origincatch == OriginCatch::PASV) {
                modifiedresponse = "227 Entering Passive Mode (" + toPASVString(rewriteaddr, boundport) + ")\r\n";
                global->log("[" + sessiontag + "] Rewriting EPSV response " + epsvstring + " -> PASV response "
                  + rewriteaddr + ":" + std::to_string(boundport));
              }
              else if (addr.empty()) {
                std::string rewrittenepsv = toExtendedPASVString(boundport);
                modifiedresponse = response.substr(0, start) + rewrittenepsv + response.substr(end);
                global->log("[" + sessiontag + "] Rewriting EPSV string " + epsvstring + " -> " + rewrittenepsv);
              }
              else {
                std::string rewrittenepsv = toExtendedPASVString(originaddrfam, rewriteaddr, boundport);
                modifiedresponse = response.substr(0, start) + rewrittenepsv + response.substr(end);
                global->log("[" + sessiontag + "] Rewriting EPSV string " + epsvstring + " -> " + rewrittenepsv);
              }
              break;
            }
            global->log("[" + sessiontag + "] Passive port range exhausted. Please make more ports available.");
            modifiedresponse = exhaustedresponse;
            break;
          }
          else {
            global->log("[" + sessiontag + "] Caught malformatted EPSV response, ignoring. (" +response + ")");
          }
        }
        break;
      case ResponseCatch::PORT:
      case ResponseCatch::EPRT:
        if (responsecatch == ResponseCatch::EPRT && origincatch == OriginCatch::PORT) {
          modifiedresponse = "200 PORT command successful.\r\n";
          global->log("[" + sessiontag + "] Rewriting EPRT success response -> PORT success response");
          break;
        }
        // only reason to end up here is to respond with port range exhausted
        global->log("[" + sessiontag + "] Passive port range exhausted. Please make more ports available.");
        modifiedresponse = exhaustedresponse;
        break;
    }
    if (!modifiedresponse.empty()) {
      respdata = &modifiedresponse[0];
      respdatalen = modifiedresponse.length();
    }
    bool pause = !session->targetData(respdata, respdatalen) && !paused;
    if (pause) {
      global->getIOManager()->pause(sockid);
      paused = true;
    }
    responseparser.reset();
    responsecatch = ResponseCatch::NONE;
    origincatch = OriginCatch::NONE;
    if (starttls) {
      global->log("[" + sessiontag + "] AUTH TLS caught, Starting MITM handshakes");
      session->negotiateTLS();
      global->getIOManager()->negotiateSSLConnect(sockid);
    }
  }
}

void BncSessionClient::FDSendComplete(int sockid) {
  session->targetSendComplete();
}

void BncSessionClient::FDSSLSuccess(int sockid, const std::string& cipher) {
  assert (tlsstate == TLSState::IN_PROGRESS);
  this->cipher = cipher;
  tlsstate = TLSState::ACTIVE;
  checkMitm();
}

void BncSessionClient::sendComplete() {
  if (paused) {
    global->getIOManager()->resume(sockid);
    paused = false;
  }
}

bool BncSessionClient::sendData(const char* data, unsigned int datalen) {
  assert (identreceived || noidnt);
  if (!traffic) {
    return global->getIOManager()->sendData(sockid, data, datalen);
  }
  if (!commandparser.parse(data, datalen)) {
    return true;
  }
  std::string command = commandparser.getCommandTrimmedUpper();
  std::string modifiedcommand;
  char* commanddata = commandparser.getCommandData();
  unsigned int commandlen = commandparser.getCommandDataLength();
  std::vector<std::string> commandwords = util::splitVec(command);
  if (tlsstate == TLSState::NONE && (command == "AUTH TLS" || command == "AUTH SSL")) {
    tlsstate = TLSState::QUERY;
    responsecatch = ResponseCatch::AUTH_TLS;
  }
  else if (command == "PASV" || command == "CPSV") {
    responsecatch = ResponseCatch::PASV;
    if (siteaddrfam == Core::AddressFamily::IPV6) {
      responsecatch = ResponseCatch::EPSV;
      modifiedcommand = "EPSV 2";
      global->log("[" + sessiontag + "] Rewriting " + command + " -> " + modifiedcommand);
      origincatch = OriginCatch::PASV;
    }
  }
  else if (commandwords[0] == "EPSV") {
    responsecatch = ResponseCatch::EPSV;
    if (siteaddrfam == Core::AddressFamily::IPV4 && command == "EPSV 2") {
      modifiedcommand = "EPSV 1";
      global->log("[" + sessiontag + "] Rewriting " + command + " -> " + modifiedcommand);
      responsecatch = ResponseCatch::EPSV;
      origincatch = OriginCatch::EPSV_2;
    }
    if (siteaddrfam == Core::AddressFamily::IPV6 && command != "EPSV 2") {
      modifiedcommand = "EPSV 2";
      global->log("[" + sessiontag + "] Rewriting " + command + " -> " + modifiedcommand);
      responsecatch = ResponseCatch::EPSV;
      origincatch = OriginCatch::EPSV_1;
    }
  }
  else if (commandwords[0] == "PORT") {
    std::string addr;
    int port;
    if (fromPASVString(commandwords[1], addr, port)) {
      global->log("[" + sessiontag + "] Caught PORT command, preparing traffic bounce session");
      int boundport = tbncsessions->activate(siteaddrfam, Core::AddressFamily::IPV4, addr, port, sessiontag);
      if (boundport != -1) {
        if (siteaddrfam == Core::AddressFamily::IPV4) {
          modifiedcommand = commandwords[0] + " " + toPASVString(siterewriteaddr, boundport);
          global->log("[" + sessiontag + "] Rewriting PORT " + addr + ":" + std::to_string(port) +
            " -> PORT " + siterewriteaddr + ":" + std::to_string(boundport));
        }
        else {
          modifiedcommand = "EPRT " + toExtendedPASVString(Core::AddressFamily::IPV6, siterewriteaddr, boundport);
          global->log("[" + sessiontag + "] Rewriting PORT " + addr + ":" + std::to_string(port) + " -> " + modifiedcommand);
          responsecatch = ResponseCatch::EPRT;
          origincatch = OriginCatch::PORT;
        }
      }
      else {
        responsecatch = ResponseCatch::PORT;
        modifiedcommand = "NOOP";
      }
    }
    else {
      global->log("[" + sessiontag + "] Caught malformatted PORT command, ignoring. (" + command + ")");
    }
  }
  else if (commandwords[0] == "EPRT") {
    Core::AddressFamily addrfam;
    std::string addr;
    int port;
    if (fromExtendedPASVString(commandwords[1], addrfam, addr, port)) {
      std::string useaddr = addr;
      if (useaddr.empty()) {
        addrfam = clientaddrfam;
        useaddr = clientaddr;
      }
      global->log("[" + sessiontag + "] Caught EPRT command, preparing traffic bounce session");
      int boundport = tbncsessions->activate(siteaddrfam, addrfam, useaddr, port, sessiontag);
      if (boundport != -1) {

        modifiedcommand = commandwords[0] + " " + toExtendedPASVString(siteaddrfam, siterewriteaddr, boundport);
        global->log("[" + sessiontag + "] Rewriting " + command + " -> " + modifiedcommand);
      }
      else {
        responsecatch = ResponseCatch::EPRT;
        modifiedcommand = "NOOP";
      }
    }
    else {
      global->log("[" + sessiontag + "] Caught malformatted EPRT command, ignoring. (" + command + ")");
    }
  }
  if (!modifiedcommand.empty()) {
    modifiedcommand += "\r\n";
    commanddata = &modifiedcommand[0];
    commandlen = modifiedcommand.length();
  }
  bool needpause = !global->getIOManager()->sendData(sockid, commanddata, commandlen);
  commandparser.reset();
  return !needpause;
}

void BncSessionClient::parentTLSSuccess(const std::string& cipher) {
  parentcipher = cipher;
  checkMitm();
}

void BncSessionClient::checkMitm() {
  if (tlsstate == TLSState::ACTIVE && !parentcipher.empty() && !cipher.empty()) {
    global->log("[" + sessiontag + "] Control channel TLS MITM established. " + parentcipher + " + " + cipher);
  }
}
