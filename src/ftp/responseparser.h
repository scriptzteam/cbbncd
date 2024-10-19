#pragma once

class FTPResponseParser {
public:
  FTPResponseParser();
  ~FTPResponseParser();
  bool parse(const char* newdata, unsigned int newdatalen);
  void reset();
  bool getResponseComplete() const;
  int getResponseCode() const;
  char* getResponseData() const;
  unsigned int getResponseDataLength() const;
private:
  unsigned int databuflen;
  char* databuf;
  unsigned int databufpos;
  int databufcode;
  bool complete;
};
