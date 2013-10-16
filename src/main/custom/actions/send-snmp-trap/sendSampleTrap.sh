#!/bin/sh
./snmpTrapSender.sh -m -a "Base App"   \
	-trig "OppsTest" \
	-n "Node900 Node800" \
	-b "login.do" \
	-tier "MainWeb" \
	-e "Mon Sep 23 08:46:55 CEST 2013" \
	-sever ERROR \
	-type "BUSINESS_TRANSACTION" \
	-summ "TEST Message 1111./snmpTrapSender.sh -h" \
	-link "http://www.google.de" \
	-tag "DumpTester"

# ./snmpTrapSender.sh -m -a "Base App" 
#	-trig "OppsTest" # Policy which triggers 
#	-n "Node900 Node800" # Node / nodelist 
#	-b "login.do"  # BT / BT List
#	-tier "MainWeb" # Tier / Tierlist
#	-e "Mon Sep 23 08:46:55 CEST 2013" 
#	-sever ERROR 
#	-type "BUSINESS_TRANSACTION"  
#	-summ "TEST MEssage 1111./snmpTrapSender.sh -h" 
#	-link "http://www.google.de" 
#	-tag "DumpTester" # Action Name
