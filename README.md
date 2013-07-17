# AppDynamics SNMP Trap Alerting Integration

##Use Case

Simple Network Management Protocol (SNMP) is a protocol for managing IP network devices such as routers, switches, servers, workstations, etc. An SNMP trap is an asynchronous notification between an SNMP agent to its SNMP manager.

With the SNMP Trap integration you can leverage your existing alerting infrastructure to notify your operations team to resolve performance degradation issues.

This tool sends SNMP trap alerts when triggered via an AppDynamics 3.6 policy violation.

##Parameters
<table>
<tbody>
<tr>
<th align="left">AppDynamics Parameters </th>
<th align="left">SNMP Parameters </th>
<th align="left">Description </th>
</tr>
<tr>
<td align="left">&nbsp;</td>
<td align="left">host </td>
<td align="left">Host of the destination where the trap is being sent </td>
</tr>
<tr>
<td align="left">&nbsp;</td>
<td align="left">port </td>
<td align="left">Port of the destination where the trap is being sent </td>
</tr>
<tr>
<td align="left">&nbsp;</td>
<td align="left"> trap-host </td>
<td align="left"> IP address of the source that is sending the trap </td>
</tr>
<tr>
<td align="left">&nbsp;</td>
<td align="left"> community </td>
<td align="left"> Community type of the SNMP trap. Default = PUBLIC <br class="atl-forced-newline" /> </td>
</tr>
<tr>
<td align="left">APP_NAME, PVN_ALERT_TIME,<br class="atl-forced-newline" /> SEVERITY,<br class="atl-forced-newline" /> POLICY_NAME,<br class="atl-forced-newline" /> AFFECTED_ENTITY_TYPE,<br class="atl-forced-newline" /> AFFECTED_ENTITY_NAME,<br class="atl-forced-newline" />
SUMMARY_MESSAGE, <br class="atl-forced-newline" /> DEEP_LINK_URL,<br class="atl-forced-newline" />
TAG </td>
<td align="left">details </td>
<td align="left">These parameters tie to SNMP specific params:
<br class="atl-forced-newline" />
<br class="atl-forced-newline" /> 
Application = APP_NAME
<br class="atl-forced-newline" /> 
Triggered By = POLICY_NAME
<br class="atl-forced-newline" /> 
Event Time = PVN_ALERT_TIME
<br class="atl-forced-newline" /> 
Severity = SEVERITY
<br class="atl-forced-newline" /> 
Type = AFFECTED_ENTITY_TYPE
<br class="atl-forced-newline" /> 
Summary = SUMMARY_MESSAGE
<br class="atl-forced-newline" /> 
Link = DEEP_LINK_URL
<br class="atl-forced-newline" />
Tag = TAG </td>
</tr>
<tr>
<td align="left">&nbsp;</td>
<td align="left"> enable-logs </td>
<td align="left"> Enables logging for debugging purposes </td>
</tr>
<tr>
<td align="left">&nbsp;</td>
<td align="left"> snmp-version </td>
<td align="left"> Trap version. (Supports v1, v2 and v3 traps) <br class="atl-forced-newline" /> </td>
</tr>
</tbody>
</table>

###Trap Version 3 specific parameters

<table><tbody>
<tr>
<th align="left">Parameter </th>
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
    <trap-host>123.232.132.122</trap-host>     
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

##Installation

1. Modify the configuration file.

    In order for a trap to be sent the configuration file **MUST**  be
modified.

    **LOCATION: root/conf/config.xml**

    The configuration file (config.xml):

    <table class='confluenceTable'>
    <tbody>
<tr>
<th class='confluenceTh'> Property </th>
<th class='confluenceTh'> Description </th>
</tr>
<tr>
<td class='confluenceTd'> host </td>
<td class='confluenceTd'> IP/URL to where the trap has to be sent </td>
</tr>
<tr>
<td class='confluenceTd'> port </td>
<td class='confluenceTd'> Port of the location where the trap has to be sent </td>
</tr>
<tr>
<td class='confluenceTd'> trap-host </td>
<td class='confluenceTd'> Source IP </td>
</tr>
<tr>
<td class='confluenceTd'> community </td>
<td class='confluenceTd'> [OPTIONAL] Defines the community type of the SNMP trap&nbsp; <br class="atl-forced-newline" /> </td>
</tr>
<tr>
<td class='confluenceTd'> enable-logs&nbsp; <br class="atl-forced-newline" /> </td>
<td class='confluenceTd'> [OPTIONAL] Enables logs for debugging purposes&nbsp; <br class="atl-forced-newline" />
<br class="atl-forced-newline" /> </td>
</tr>
<tr>
<td class='confluenceTd'> snmp-version </td>
<td class='confluenceTd'> V1 = 1, V2 = 2, V3 = 3 </td>
</tr>
</tbody>
</table>


    If snmp-version = 3 then:
    <table>
<tbody>
<tr>
<th class='confluenceTh'> Property </th>
<th class='confluenceTh'> Description </th>
</tr>
<tr>
<td class='confluenceTd'> security-level </td>
<td class='confluenceTd'> 1 = NoAuthNoPriv, 2 = AuthNoPriv, 3 = AuthPriv </td>
</tr>
<tr>
<td class='confluenceTd'> username </td>
<td class='confluenceTd'> Username for trap authentication </td>
</tr>
<tr>
<td class='confluenceTd'> password </td>
<td class='confluenceTd'> Password for trap authentication </td>
</tr>
<tr>
<td class='confluenceTd'> auth-protocol </td>
<td class='confluenceTd'> Authentication Protocol. SHA or MD5 </td>
</tr>
<tr>
<td class='confluenceTd'> priv-protocol </td>
<td class='confluenceTd'> Privacy Protocol. (AES256, AES192, AES128, 3DES, DES) </td>
</tr>
<tr>
<td class='confluenceTd'> priv-protocol-password </td>
<td class='confluenceTd'> Privacy password </td>
</tr>
</tbody>
</table>


2. Install Custom Actions

    2.1  To create a Custom Action, first refer to [Installing Custom
    Actions into the
    Controller](http://docs.appdynamics.com/display/PRO12S/Configure+Custom+Notifications#ConfigureCustomNotifications-InstallingCustomActionsontheController) (login required).

    2.2  Copy all the contents found in the **dist** folder to the custom
    notification folder created in the above step. 
     i.e.
    \<controller-home\>/custom/actions/\<directory\_created\_in\_step\_1\>/

##Debugging

To debug the code:

1.  Modify the config file and enable logs.


	~~~~
    <enable-logs>true</enable-logs>
	~~~~

2.  Open \<custom\_action\_directory\>/logs/snmpTrapSender.log

##Using the jar file as a standalone

The jar file can be used as a standalone. For information enter "--help" when running the jar:

	~~~~
    java -jar SNMPTrapSender.jar --help
   	~~~~



##Contributing

Always feel free to fork and contribute any changes directly via [GitHub](https://github.com/Appdynamics/snmptrap-alerting-extension).

##Community

Find out more in the [AppSphere](http://appsphere.appdynamics.com/t5/Extensions/SNMP-Trap-Alerting-Extension/idi-p/825) community.

##Support

For any questions or feature request, please contact [AppDynamics Center of Excellence](mailto://ace-request@appdynamics.com).
