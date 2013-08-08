@echo off
java -Dlog4j.configuration=file:..\..\conf/log4j.xml -jar ..\..\lib\SNMPTrapSender.jar %*
