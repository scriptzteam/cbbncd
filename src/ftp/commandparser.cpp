#include "commandparser.h"

#include <cstring>
#include <locale>

#define DATA_BUF_SIZE 256

FTPCommandParser::FTPCommandParser() : databuflen(DATA_BUF_SIZE),
  databuf(static_cast<char*>(malloc(databuflen))), databufpos(0),
  complete(false)
{

}

FTPCommandParser::~FTPCommandParser() {
  delete databuf;
}

bool FTPCommandParser::parse(const char* newdata, unsigned int newdatalen) {
  if (databufpos + newdatalen > databuflen) {
    while (databufpos + newdatalen > databuflen) {
      databuflen *= 2;
    }
    char* newdatabuf = static_cast<char*>(malloc(databuflen));
    memcpy(newdatabuf, databuf, databufpos);
    delete databuf;
    databuf = newdatabuf;
  }
  memcpy(databuf + databufpos, newdata, newdatalen);
  databufpos += newdatalen;
  if (databuf[databufpos - 1] == '\n') {
    complete = true;
  }
  return complete;
}

void FTPCommandParser::reset() {
  databufpos = 0;
  complete = false;
}

bool FTPCommandParser::getCommandComplete() const {
  return complete;
}

char* FTPCommandParser::getCommandData() const {
  return databuf;
}

unsigned int FTPCommandParser::getCommandDataLength() const {
  return databufpos;
}

std::string FTPCommandParser::getCommandTrimmedUpper() const {
  std::string command(databuf, databufpos);
  int cutafterpos = command.length() - 1;
  while (cutafterpos >= 0 && (command[cutafterpos] == '\n' || command[cutafterpos] == '\r')) {
    --cutafterpos;
  }
  for (int i = 0; i <= cutafterpos; ++i) {
    command[i] = std::toupper(command[i]);
  }
  return command.substr(0, cutafterpos + 1);
}
