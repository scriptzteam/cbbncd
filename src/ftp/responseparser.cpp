#include "responseparser.h"

#include <cstring>
#include <string>

#define DATA_BUF_SIZE 2048

FTPResponseParser::FTPResponseParser() : databuflen(DATA_BUF_SIZE),
  databuf(static_cast<char*>(malloc(databuflen))), databufpos(0),
  databufcode(0), complete(false)
{

}

FTPResponseParser::~FTPResponseParser() {
  delete databuf;
}

bool FTPResponseParser::parse(const char* newdata, unsigned int newdatalen) {
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
  bool messagecomplete = false;
  char* loc = 0;
  if(databuf[databufpos - 1] == '\n') {
    loc = databuf + databufpos - 5;
    while (loc >= databuf) {
      if (isdigit(*loc) && isdigit(*(loc+1)) && isdigit(*(loc+2))) {
        if ((*(loc+3) == ' ' || *(loc+3) == '\n') && (loc == databuf || *(loc-1) == '\n')) {
          messagecomplete = true;
          databufcode = atoi(std::string(loc, 3).data());
          break;
        }
      }
      --loc;
    }
  }
  if (messagecomplete) {
    if (databufcode == 550) {
      // workaround for a glftpd bug causing an extra row '550 Unable to load your own user file!.' on retr/stor
      if (*(loc+4) == 'U' && *(loc+5) == 'n' && *(loc+28) == 'u' && *(loc+33) == 'f') {
        databufpos = 0;
        complete = false;
        return false;
      }
    }
    else {
      complete = true;
    }
  }
  else if (newdatalen == databufpos && newdatalen >= 3 && (!isdigit(*databuf) ||
           !isdigit(*(databuf+1)) || !isdigit(*(databuf+2))))
  {
    databufcode = 0;
    return true;
  }
  return messagecomplete;
}

void FTPResponseParser::reset() {
  databufpos = 0;
  complete = false;
}

bool FTPResponseParser::getResponseComplete() const {
  return complete;
}

int FTPResponseParser::getResponseCode() const {
  return databufcode;
}

char* FTPResponseParser::getResponseData() const {
  return databuf;
}

unsigned int FTPResponseParser::getResponseDataLength() const {
  return databufpos;
}
