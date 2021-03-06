# AppDynamics SNMP Trap Alerting Integration

##Use Case

Simple Network Management Protocol (SNMP) is a protocol for managing IP network devices such as routers, switches, 
servers, workstations, etc. An SNMP trap is an asynchronous notification between an SNMP agent to its SNMP manager.

With the SNMP Trap integration you can leverage your existing alerting infrastructure to notify your operations team
to resolve performance degradation issues.

This tool sends SNMP trap alerts when triggered via an AppDynamics 3.6/3.7 policy violation and can be configured
as a custom action (see Installation). 



##Installation

1. Download the SNMPTrapAlertingExtension zip from [AppDynamics Exchange](http://community.appdynamics.com/t5/AppDynamics-eXchange/idb-p/extensions)  

2. Unzip the SNMPTrapAlertingExtension.zip file into <CONTROLLER_HOME_DIR>/custom/actions/ . You should have <CONTROLLER_HOME_DIR>/custom/actions/SNMPTrapAlertingExtension created. 

3. Check if you have custom.xml file in <CONTROLLER_HOME_DIR>/custom/actions/ directory. If yes, add the following xml to the <custom-actions> element.
    
        ```
            <action>
                 <type>SNMPTrapAlertingExtension</type>
                 <!-- For Linux/Unix *.sh -->
                 <executable>snmpTrapSender.sh</executable>
                 <!-- For windows *.bat -->
                 <!--<executable>snmpTrapSender.bat</executable>-->
            </action>
        ```
     If you don't have custom.xml already, create one with the below xml content. 
     
     ```
            <custom-actions>
            <action>
                 <type>SNMPTrapAlertingExtension</type>
                 <!-- For Linux/Unix *.sh -->
                 <executable>snmpTrapSender.sh</executable>
                 <!-- For windows *.bat -->
                 <!--<executable>snmpTrapSender.bat</executable>-->
            </action>
            </custom-actions>
     ```
     Uncomment the appropriate executable tag based on windows or linux/unix machine.
     
 4. cd into <Controller-install-dir>/custom/conf/SNMPTrapAlertingExtension and edit the config.xml configuration file.
 
 
	###Parameters
	<table>
	<tbody>
	<tr>
	<th align="left">SNMP Parameters </th>
	<th align="left">Description </th>
	</tr>
	<tr>
	<td align="left">host </td>
	<td align="left">Host of the destination where the trap is being sent </td>
	</tr>
	<tr>
	<td align="left">port </td>
	<td align="left">Port of the destination where the trap is being sent </td>
	</tr>
	<tr>
	<td align="left"> trap-host </td>
	<td align="left"> IP address of the source that is sending the trap </td>
	</tr>
	<tr>
	<td align="left"> community </td>
	<td align="left"> Community type of the SNMP trap. Default = PUBLIC <br class="atl-forced-newline" /> </td>
	</tr>
	<tr>
	<td align="left"> enable-logs </td>
	<td align="left"> Enables logging for debugging purposes </td>
	</tr>
	<tr>
	<td align="left"> snmp-version </td>
	<td align="left"> Trap version. (Supports v1, v2 and v3 traps) <br class="atl-forced-newline" /> </td>
	</tr>
	</tbody>
	</table>
	
	####Trap Version 3 specific parameters
	
	<table><tbody>
	<tr>
	<th align="left">SNMP Parameters </th>
	<th align="left">Description </th>
	</tr><tr>
	<td > security-level </td>
	<td align="left"> NoAuthNoPriv = 1&nbsp; <br class="atl-forced-newline" />
	AuthNoPriv = 2 <br class="atl-forced-newline" />
	AuthPriv = 3 <br class="atl-forced-newline" />
	<br class="atl-forced-newline" />
	If necessary, see <a href="http://www.webnms.com/simulator/help/sim_network/netsim_conf_snmpv3.html">information on security levels</a>.
	</td>
	</tr>
	<tr>
	<td align="left"> username </td>
	<td align="left"> Username to validate trap </td>
	</tr>
	<tr>
	<td align="left"> password </td>
	<td align="left"> Password to validate trap. Required for security-level greater than 1 </td>
	</tr>
	<tr>
	<td align="left"> auth-protocol </td>
	<td align="left"> Authentication Protocol (MD5 or SHA). Required for security-level greater than 1 </td>
	</tr>
	<tr>
	<td align="left"> priv-protocol </td>
	<td align="left"> Privacy Protocol. Required for security-level = 3 (AuthPriv) <br class="atl-forced-newline" />
	<br class="atl-forced-newline" />
	Supports: <br class="atl-forced-newline" />
	<ul>
		<li>AES256</li>
		<li>AES192</li>
		<li>AES128</li>
		<li>3DES</li>
		<li>DES</li>
	</ul>
	</td>
	</tr>
	<tr>
	<td align="left"> priv-protocol-password </td>
	<td align="left"> Privacy protocol password. Required for security-level = 3 (AuthPriv) </td>
	</tr>
	</tbody>
	</table>

	###Example:
	
	~~~~
	<snmp-trap>
		<host>localhost</host>
	    <port>9000</port>    
	    <community>PUBLIC</community>     
	    <trap-host>172.16.0.0</trap-host>     
	    <enable-logs>true</enable-logs>     
	    <snmp-version>3</snmp-version>     
	    <!--Only requred if version set to 3.-->     
	    <v3>         
	    	<security-level>2</security-level>         
	    	<username>username</username>         
	   		<password>password</password>         
	    	<auth-protocol>SHA</auth-protocol>         
	    	<priv-protocol>DES</priv-protocol>         
	    	<priv-protocol-password>password</priv-protocol-password>     
	  	</v3> 
	  </snmp-trap> 
	         
	~~~~
	
5. Now you are ready to use this extension as a custom action. In the AppDynamics UI, go to 'Alert & Respond' -> 'Actions'. 
   Click on the 'Create Action' button. Select 'Custom Action' and click OK. In the drop-down menu you can find the action called 'SNMPTrapAlertingExtension'.

6. Use the MIB file <CONTROLLER_HOME_DIR>/custom/actions/SNMPTrapAlertingExtension/conf/APPD-CTLR-MIB.mib to interpret the trap at the trap receiver.

##Debugging

To debug the code:

1.  Modify the config file and enable logs.


	~~~~
    <enable-logs>true</enable-logs>
	~~~~

2.  Open \<custom\_action\_directory\>/logs/snmpTrapSender.log

##Testing

If you'd like to send a test trap for Debug purpose please use the sendSampleTrap.sh script. This Script will send a simple Trap using the Action Configuration. You can use this to verify that the transmission works and the Trap would be received *without* the need of producing a real error or event.


##Using the jar file as a standalone

The jar file can be used as a standalone. For information enter "--help" when running the jar:

	```
    For Windows,
    
    ..\..\..\jdk\bin\java -Dlog4j.configuration=file:conf\log4j.xml -DSNMP_TRAP_SENDER_HOME=. -jar .\lib\SNMPTrapSender.jar --help
    
    
    For Linux/Unix,
    
    ../../../jdk/bin/java -Dlog4j.configuration=file:conf/log4j.xml -DSNMP_TRAP_SENDER_HOME=. -jar ./lib/SNMPTrapSender.jar --help
   	```



##Contributing

Always feel free to fork and contribute any changes directly via [GitHub](https://github.com/Appdynamics/snmptrap-alerting-extension).

##Community

Find out more in the [AppSphere](http://appsphere.appdynamics.com/t5/Extensions/SNMP-Trap-Alerting-Extension/idi-p/825) community.

##Support

For any questions or feature request, please contact [AppDynamics Center of Excellence](mailto:ace-request@appdynamics.com).
