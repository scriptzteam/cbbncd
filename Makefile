-include Makefile.inc

SHELL := /bin/bash

HAS_PBKDF2 := $(shell openssl enc -pbkdf2 > /dev/null 2>&1 < /dev/null; echo $$?)
ifeq ($(HAS_PBKDF2), 0)
PBKDF2_FLAG := -pbkdf2
endif
AES256_CMD = openssl enc -a -A $(PBKDF2_FLAG) -aes-256-cbc -md sha256

LINK = src/core/libcore.a -lssl -lpthread -lcrypto

all: application

application: core
# This mess is unreadable. I really really wanted to put the config in the Makefile. I'm sorry.
	$(eval LASTPORT := $(shell cat .last 2>/dev/null|grep 'port='|cut -d '=' -f 2))
	$(eval LASTPORT := $(shell if [ -n "$(LASTPORT)" ]; then echo $(LASTPORT); else echo "65432"; fi))
	$(eval USEPORT := $(shell if [ -z "$(PORT)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Listen port [$(LASTPORT)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTPORT); fi); else echo $(PORT); fi))
	$(eval LASTHOST := $(shell cat .last 2>/dev/null|grep 'host='|cut -d '=' -f 2))
	$(eval LASTHOST := $(shell if [ -n "$(LASTHOST)" ]; then echo $(LASTHOST); else echo "ftp.example.com:21"; fi))
	$(eval USEHOST := $(shell if [ -z "$(HOST)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Target host [$(LASTHOST)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTHOST); fi); else echo $(HOST); fi))
	$(eval LASTIDENT := $(shell cat .last 2>/dev/null|grep 'ident='|cut -d '=' -f 2))
	$(eval LASTIDENT := $(shell if [ -z "$(LASTIDENT)" ] || [ "$(LASTIDENT)" != "false" ]; then echo "true"; else echo "false"; fi))
	$(eval USEIDENT := $(shell if [ -z "$(IDENT)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Ident lookup [$(shell if [ $(LASTIDENT) == "false" ]; then echo "n"; else echo "y"; fi)]: "; if [ -n "$$REPLY" ]; then if [ "$$REPLY" != "n" ]; then echo "true"; else echo "false"; fi; else echo "$(LASTIDENT)"; fi); else echo $(IDENT); fi))
	$(eval LASTNOIDNT := $(shell cat .last 2>/dev/null|grep 'noidnt='|cut -d '=' -f 2))
	$(eval LASTNOIDNT := $(shell if [ -z "$(LASTNOIDNT)" ] || [ "$(LASTNOIDNT)" != "true" ]; then echo "false"; else echo "true"; fi))
	$(eval USENOIDNT := $(shell if [ "$(USEIDENT)" == "false" ]; then if [ -z "$(NOIDNT)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Disable IDNT completely [$(shell if [ $(LASTNOIDNT) == "false" ]; then echo "n"; else echo "y"; fi)]: "; if [ -n "$$REPLY" ]; then if [ "$$REPLY" != "y" ]; then echo "false"; else echo "true"; fi; else echo $(LASTNOIDNT); fi); else echo $(NOIDNT); fi; else echo "false"; fi))
	$(eval LASTBIND := $(shell cat .last 2>/dev/null|grep 'bind='|cut -d '=' -f 2))
	$(eval LASTBIND := $(shell if [ -z "$(LASTBIND)" ] || [ "$(LASTBIND)" != "true" ]; then echo "false"; else echo "true"; fi))
	$(eval USEBIND := $(shell if [ -z "$(BIND)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Bind to specific IPs or interface [$(shell if [ $(LASTBIND) == "false" ]; then echo "n"; else echo "y"; fi)]: "; if [ -n "$$REPLY" ]; then if [ "$$REPLY" != "n" ]; then echo "true"; else echo "false"; fi; else echo "$(LASTBIND)"; fi); else echo $(BIND); fi))
	$(eval LASTIPIF := $(shell cat .last 2>/dev/null|grep 'ipif='|cut -d '=' -f 2))
	$(eval LASTIPIF := $(shell if [ -n "$(LASTIPIF)" ]; then echo $(LASTIPIF); else echo "0.0.0.0"; fi))
	$(eval USEIPIF := $(shell if [ "$(USEBIND)" == "true" ]; then if [ -z "$(IPIF)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "IPs or network interface [$(LASTIPIF)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTIPIF); fi); else echo $(IPIF); fi; else echo $(LASTIPIF); fi))
	$(eval LASTTRAFFIC := $(shell cat .last 2>/dev/null|grep 'traffic='|cut -d '=' -f 2))
	$(eval LASTTRAFFIC := $(shell if [ -z "$(LASTTRAFFIC)" ] || [ "$(LASTTRAFFIC)" != "true" ]; then echo "false"; else echo "true"; fi))
	$(eval USETRAFFIC := $(shell if [ -z "$(TRAFFIC)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Bounce traffic [$(shell if [ $(LASTTRAFFIC) == "false" ]; then echo "n"; else echo "y"; fi)]: "; if [ -n "$$REPLY" ]; then if [ "$$REPLY" != "n" ]; then echo "true"; else echo "false"; fi; else echo "$(LASTTRAFFIC)"; fi); else echo $(TRAFFIC); fi))
	$(eval LASTNAT := $(shell cat .last 2>/dev/null|grep 'nat='|cut -d '=' -f 2))
	$(eval LASTNAT := $(shell if [ -z "$(LASTNAT)" ] || [ "$(LASTNAT)" != "true" ]; then echo "false"; else echo "true"; fi))
	$(eval USENAT := $(shell if [ "$(USETRAFFIC)" == "true" ]; then if [ -z "$(NAT)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Use external NAT IP (is the BNC behind NAT?) [$(shell if [ $(LASTNAT) == "false" ]; then echo "n"; else echo "y"; fi)]: "; if [ -n "$$REPLY" ]; then if [ "$$REPLY" != "n" ]; then echo "true"; else echo "false"; fi; else echo "$(LASTNAT)"; fi); else echo $(NAT); fi; else echo $(LASTNAT); fi))
	$(eval LASTNATIP := $(shell cat .last 2>/dev/null|grep 'natip='|cut -d '=' -f 2))
	$(eval LASTNATIP := $(shell if [ -n "$(LASTNATIP)" ]; then echo $(LASTNATIP); else echo "0.0.0.0"; fi))
	$(eval USENATIP := $(shell if [ "$(USENAT)" == "true" ]; then if [ -z "$(NATIP)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "External NAT IP [$(LASTNATIP)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTNATIP); fi); else echo $(NATIP); fi; else echo $(LASTNATIP); fi))
	$(eval LASTPASVPORTRANGE := $(shell cat .last 2>/dev/null|grep 'pasvportrange='|cut -d '=' -f 2))
	$(eval LASTPASVPORTRANGE := $(shell if [ -n "$(LASTPASVPORTRANGE)" ]; then echo $(LASTPASVPORTRANGE); else echo "50000-50100"; fi))
	$(eval USEPASVPORTRANGE := $(shell if [ "$(USETRAFFIC)" == "true" ]; then if [ -z "$(PASVPORTRANGE)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Passive port range [$(LASTPASVPORTRANGE)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTPASVPORTRANGE); fi); else echo $(PASVPORTRANGE); fi; else echo $(LASTPASVPORTRANGE); fi))
	$(eval LASTAUTOGENCERT := $(shell cat .last 2>/dev/null|grep 'autogencert='|cut -d '=' -f 2))
	$(eval LASTAUTOGENCERT := $(shell if [ -z "$(LASTAUTOGENCERT)" ] || [ "$(LASTAUTOGENCERT)" != "false" ]; then echo "true"; else echo "false"; fi))
	$(eval USEAUTOGENCERT := $(shell if [ "$(USETRAFFIC)" == "true" ] && ([ -z "$(AUTOGENCERT)" ] && [ -z "$(DATA)" ]); then echo $$(read -p "Auto-generate private key and certificate [$(shell if [ $(LASTAUTOGENCERT) == "false" ]; then echo "n"; else echo "y"; fi)]: "; if [ -n "$$REPLY" ]; then if [ "$$REPLY" != "n" ]; then echo "true"; else echo "false"; fi; else echo "$(LASTAUTOGENCERT)"; fi); else echo $(AUTOGENCERT); fi))
	$(eval LASTCERTFILE := $(shell cat .last 2>/dev/null|grep 'certfile='|cut -d '=' -f 2))
	$(eval LASTCERTFILE := $(shell if [ -n "$(LASTCERTFILE)" ]; then echo $(LASTCERTFILE); else echo ""; fi))
	$(eval USECERTFILE := $(shell if [ "$(USETRAFFIC)" == "true" ] && [ "$(USEAUTOGENCERT)" == "false" ]; then if [ -z "$(CERTFILE)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Certificate file [$(LASTCERTFILE)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTCERTFILE); fi); else echo $(CERTFILE); fi; else echo $(LASTCERTFILE); fi))
	$(eval GENKEY := $(shell if [ "$(USETRAFFIC)" == "true" ] && ([ "$(USEAUTOGENCERT)" == "true" ] || [ -z "$(USECERTFILE)" ]); then openssl ecparam -outform der -name prime256v1 -genkey | openssl base64 -A; else echo ""; fi))
	$(eval GENCERT := $(shell if [ -n "$(GENKEY)" ]; then echo $(GENKEY) | openssl base64 -d | openssl req -new -key /dev/stdin -keyform der -x509 -nodes -days 365 -outform der -subj '/CN=AQ/' | openssl base64 -A; else echo -n ""; fi))
	$(eval USECERT := $(shell if [ "$(USEAUTOGENCERT)" == "false" ]; then openssl x509 -in $(USECERTFILE) -outform der | openssl base64 -A; else echo $(GENCERT); fi))
	$(eval USEKEY := $(shell if [ "$(USEAUTOGENCERT)" == "false" ] && [ -n "$(USECERTFILE)" ]; then openssl pkey -in $(USECERTFILE) -outform der 2>/dev/null | openssl base64 -A; fi))
	$(eval LASTKEYFILE := $(shell cat .last 2>/dev/null|grep 'keyfile='|cut -d '=' -f 2))
	$(eval LASTKEYFILE := $(shell if [ -n "$(LASTKEYFILE)" ]; then echo $(LASTKEYFILE); else echo ""; fi))
	$(eval USEKEYFILE := $(shell if [ "$(USETRAFFIC)" == "true" ] && [ "$(USEAUTOGENCERT)" == "false" ] && [ -n "$(USECERTFILE)" ] && [ -z $(USEKEY) ]; then if [ -z "$(KEYFILE)" ] && [ -z "$(DATA)" ]; then echo $$(read -p "Private key file [$(LASTKEYFILE)]: "; if [ -n "$$REPLY" ]; then echo $$REPLY; else echo $(LASTKEYFILE); fi); else echo $(KEYFILE); fi; else echo ""; fi))
	$(eval USEKEY := $(shell if [ -z "$(USEKEY)" ] && [ -n "$(USEKEYFILE)" ]; then openssl pkey -in $(USEKEYFILE) -outform der | openssl base64 -A; else echo $(USEKEY); fi))
	$(eval USEKEY := $(shell if [ -z "$(USEKEY)" ] && [ -n "$(GENKEY)" ]; then echo $(GENKEY); else echo $(USEKEY); fi))
	@if [ "$(USETRAFFIC)" == "true" ] && [ -z "$(USEKEY)" ]; then echo -e "ERROR: No private key found."; exit 1; fi
	$(eval ENCRYPT := $(shell if ( [ "$(USETRAFFIC)" == "false" ] || [ -n "$(USEKEY)" ]) && [ -z "$(DATA)" ] && ( [ -z "$(PORT)" ] || [ -z "$(HOST)" ] || [ -z "$(IDENT)" ] || [ -z "$(IPIF)" ] || [ -z "$(TRAFFIC)" ]); then echo $$(read -p "Encrypt data [y]: "; if [ -z "$$REPLY" ] || [ "$$REPLY" != "n" ]; then echo "1"; else echo ""; fi); fi))
	$(eval LASTDATA := port=$(USEPORT);host=$(USEHOST);ident=$(USEIDENT);noidnt=$(USENOIDNT);bind=$(USEBIND);ipif=$(USEIPIF);traffic=$(USETRAFFIC);nat=$(USENAT);natip=$(USENATIP);pasvportrange=$(USEPASVPORTRANGE);autogencert=$(USEAUTOGENCERT);certfile=$(USECERTFILE);keyfile=$(USEKEYFILE))
	$(eval AGGDATA := port=$(USEPORT);host=$(USEHOST);ident=$(USEIDENT);noidnt=$(USENOIDNT);bind=$(USEBIND);ipif=$(USEIPIF);traffic=$(USETRAFFIC);nat=$(USENAT);natip=$(USENATIP);pasvportrange=$(USEPASVPORTRANGE);cert=$(USECERT);key=$(USEKEY))
	$(eval ENCDATA := $(shell if [ -n "$(ENCRYPT)" ]; then echo -n "$(AGGDATA)" | $(AES256_CMD); fi))
	@rm -f .last
	@if [ -z "$(DATA)" ] && ( [ -z "$(ENCRYPT)" ] || [ -z "$(ENCDATA)" ] ); then echo "$(LASTDATA)" | sed s/\;/\\n/g > .last; fi
	@if [ -n "$(ENCRYPT)" ] && [ -z "$(ENCDATA)" ]; then echo -e "WARNING: Proceeding without encryption."; fi
	$(eval DATA := $(shell if [ -z "$(DATA)" ]; then echo $$(if [ -n "$(ENCDATA)" ]; then echo $(ENCDATA); else echo "$(AGGDATA)"; fi); fi))
	g++ $(ALLFLAGS) -o cbbncd -DBNCDATA="\"$(DATA)\"" $(wildcard src/*.cpp src/bnc/*.cpp src/ftp/*.cpp) $(LINK)

core:
	@+$(MAKE) -C src/core

clean:
	@+$(MAKE) -C src/core clean
	rm -f .last cbbncd
