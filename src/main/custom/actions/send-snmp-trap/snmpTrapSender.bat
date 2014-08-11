@echo off
..\..\..\jdk\bin\java -Dlog4j.configuration=file:conf\log4j.xml -DSNMP_TRAP_SENDER_HOME=. -jar .\lib\SNMPTrapSender.jar %*
