#pragma once

#include <map>
#include <vector>

#include "core/eventreceiver.h"

class ListenPortManager : private Core::EventReceiver {
public:
  ListenPortManager(int firstport = 50000, int lastport = 50100);
  ~ListenPortManager();
  void setPortRange(int first, int last);
  int acquirePort();
  void releasePort(int port);
  void markPortUnavailable(int port);
private:
  void tick(int message) override;
  std::vector<bool> availableports;
  std::map<int, unsigned int> unavailableports;
  int firstport;
  int lastport;
};
