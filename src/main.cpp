#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <list>
#include <string>
#include <sstream>

#include "core/workmanager.h"
#include "core/tickpoke.h"
#include "core/iomanager.h"
#include "core/sslmanager.h"
#include "core/types.h"

#include "bnc/bnc.h"

#include "address.h"
#include "crypto.h"
#include "globalcontext.h"
#include "listenportmanager.h"
#include "util.h"

namespace {

struct Configuration {
  int listenport = 65432;
  std::list<Address> siteaddrs;
  bool ident = true;
  bool noidnt = false;
  bool bind = false;
  std::string ipif = "0.0.0.0";
  bool traffic = false;
  bool nat = false;
  std::list<Address> natips;
  int pasvportfirst = 50000;
  int pasvportlast = 50100;
  std::string cert;
  std::string key;
};

void showInput(bool show) {
  termios tty;
  tcgetattr(STDIN_FILENO, &tty);
  if (show) {
    tty.c_lflag |= ECHO;
  }
  else {
    tty.c_lflag &= ~ECHO;
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

Core::BinaryData getPassphrase() {
  std::cerr << "Passphrase: ";
  showInput(false);
  std::string passphrase;
  std::getline(std::cin, passphrase);
  std::cerr << std::endl;
  showInput(true);
  return Core::BinaryData(passphrase.begin(), passphrase.end());
}

void daemonize() {
  pid_t pid;
  if ((pid = fork())) {
    std::cerr << "Started in daemon mode as pid " <<  pid << "." << std::endl;
    exit(0);
  }
  setsid();
  chdir("/");
  umask(0);
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  open("/dev/null", O_RDONLY);
  open("/dev/null", O_WRONLY);
  open("/dev/null", O_WRONLY);
}

Configuration parseData(const std::string& data) {
  Configuration cfg;
  std::list<std::string> params = util::split(data, ";");
  for (const std::string& param : params) {
    size_t sep = param.find("=");
    std::string key = param.substr(0, sep);
    std::string value = param.substr(sep + 1);
    if (key == "port") {
      cfg.listenport = std::stol(value);
    }
    else if (key == "host") {
      cfg.siteaddrs = parseAddresses(value);
    }
    else if (key == "ident") {
      cfg.ident = value == "true";
    }
    else if (key == "noidnt") {
      cfg.noidnt = value == "true";
    }
    else if (key == "bind") {
      cfg.bind = value == "true";
    }
    else if (key == "ipif") {
      cfg.ipif = value;
    }
    else if (key == "traffic") {
      cfg.traffic = value == "true";
    }
    else if (key == "nat") {
      cfg.nat = value == "true";
    }
    else if (key == "natip") {
      cfg.natips = parseAddresses(value);
    }
    else if (key == "pasvportrange") {
      std::list<std::string> tokens = util::split(value, "-");
      cfg.pasvportfirst = std::stol(tokens.front());
      cfg.pasvportlast = std::stol(tokens.back());
    }
    else if (key == "cert") {
      cfg.cert = value;
    }
    else if (key == "key") {
      cfg.key = value;
    }
  }
  return cfg;
}

}

int main(int argc, char** argv) {
  bool daemon = false;
  if (argc >= 2) {
    if (!strcmp(argv[1], "-d") || !strcmp(argv[1], "--daemon")) {
      daemon = true;
    }
    else {
      std::cerr << "Usage: ./cbbncd [-d]" << std::endl << "  -d, --daemon    Start in daemon mode"  << std::endl;
      return 1;
    }
  }
  std::string data = BNCDATA;
  if (data.find(";") == std::string::npos) {
    Core::BinaryData passphrase = getPassphrase();
    Core::BinaryData decodeddata;
    Crypto::base64Decode(Core::BinaryData(data.begin(), data.end()), decodeddata);
    Core::BinaryData decrypteddata;
    Crypto::decrypt(decodeddata, passphrase, decrypteddata);
    if (!Crypto::isMostlyASCII(decrypteddata)) {
      std::cerr << "Error: Passphrase invalid. Exiting." << std::endl;
      exit(1);
    }
    data = std::string(decrypteddata.begin(), decrypteddata.end());
  }
  Configuration cfg = parseData(data);

  if (daemon) {
    daemonize();
  }
  else {
    global->setVerbose(true);
    global->log("Starting in verbose foreground mode. Use -d to start in daemon mode.");
    global->log("Listening for incoming connections on port " + std::to_string(cfg.listenport));
    std::string idnt = cfg.noidnt ? "disabled" : "enabled";
    global->log("IDNT sending is " + idnt);
    std::string traffic = cfg.traffic ? "enabled" : "disabled";
    global->log("Traffic bouncing is " + traffic);
    if (cfg.traffic && cfg.nat) {
      std::string natip = cfg.nat ? "enabled" : "disabled";
      global->log("External NAT IP rewrite is " + natip);
    }
  }
  Core::WorkManager* wm = new Core::WorkManager();
  Core::TickPoke* tp = new Core::TickPoke(*wm);
  Core::IOManager* iom = new Core::IOManager(*wm, *tp);
  if (cfg.bind) {
    std::list<std::pair<std::string, std::string>> ifs = iom->listInterfaces();
    bool isif = false;
    for (const std::pair<std::string, std::string>& interface : ifs) {
      if (cfg.ipif == interface.first) {
        isif = true;
        break;
      }
    }
    if (isif) {
      iom->setBindInterface(cfg.ipif);
    }
    else {
      std::list<Address> addrs = parseAddresses(cfg.ipif);
      for (const Address& addr : addrs) {
        iom->setBindAddress(addr.addrfam, addr.host);
      }
    }
  }
  global->linkComponents(wm, iom, tp);

  std::shared_ptr<ListenPortManager> lpm = std::make_shared<ListenPortManager>(cfg.pasvportfirst, cfg.pasvportlast);
  global->linkComponents(lpm);
  std::shared_ptr<Bnc> bnc = std::make_shared<Bnc>(cfg.listenport, cfg.siteaddrs, cfg.ident, cfg.noidnt, cfg.traffic, cfg.nat, cfg.natips, cfg.pasvportfirst, cfg.pasvportlast);
  wm->init("cbbncd");
  iom->init("cbbncd");
  if (!cfg.cert.empty() && !cfg.key.empty()) {
    Core::BinaryData certdata;
    Core::BinaryData keydata;
    Crypto::base64Decode(Core::BinaryData(cfg.cert.begin(), cfg.cert.end()), certdata);
    Crypto::base64Decode(Core::BinaryData(cfg.key.begin(), cfg.key.end()), keydata);
    Core::SSLManager::addCertKeyPair(keydata, certdata);
  }
  tp->tickerLoop();
}
