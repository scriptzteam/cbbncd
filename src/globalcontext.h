#pragma once

#include <memory>
#include <string>

namespace Core {
class IOManager;
class WorkManager;
class TickPoke;
}
class ListenPortManager;

class GlobalContext {
  private:
    Core::IOManager* iom;
    Core::WorkManager* wm;
    Core::TickPoke* tp;
    std::shared_ptr<ListenPortManager> lpm;
    bool verbose;
  public:
    GlobalContext();
    virtual ~GlobalContext();
    void linkComponents(Core::WorkManager* wm, Core::IOManager* iom, Core::TickPoke* tp);
    void linkComponents(const std::shared_ptr<ListenPortManager>& lpm);
    Core::WorkManager* getWorkManager();
    Core::IOManager* getIOManager();
    Core::TickPoke* getTickPoke();
    std::shared_ptr<ListenPortManager> getListenPortManager() const;
    void setVerbose(bool);
    void log(const std::string& text);
};

extern GlobalContext* global;
