#pragma once

#include <string>

class FTPCommandParser {
public:
  FTPCommandParser();
  ~FTPCommandParser();
  bool parse(const char* newdata, unsigned int newdatalen);
  void reset();
  bool getCommandComplete() const;
  char* getCommandData() const;
  unsigned int getCommandDataLength() const;
  std::string getCommandTrimmedUpper() const;
private:
  unsigned int databuflen;
  char* databuf;
  unsigned int databufpos;
  bool complete;
};

