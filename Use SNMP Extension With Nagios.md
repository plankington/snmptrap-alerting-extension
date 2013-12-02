# Using the AppDynamics SNMP Alerting Extension with Nagios


You can send SNMP Traps from the AppDynamics SNMPTrap alerting extension to Nagios. Doing so requires configuring Nagios, Net-SNMP, SNMPTT, and Nagios SNMP Trap Interface (NSTI). This document details how to perform these configuration tasks.

The following illustration shows how SNMPTT works:
<br />
  
![](https://raw.github.com/Appdynamics/snmptrap-alerting-extension/master/integration_01.png)

<br />

This is how the implementation works after the integration:
<br />

![](https://raw.github.com/Appdynamics/snmptrap-alerting-extension/master/integration_02.png)
<br />

Basically all traps received by Net-SNMP’s snmptrapd service are written to files. The service then invokes the snmpttraphandler script, which calls the snmptt service. The snmptt service parses the trap from files. 

In accordance to the configuration of snmptt, and other MIB(s) imported into snmptt, snmptt will parse the parameters, translate the OID(s) if needed, and then push data to logs and SQL database configured. Nagios then retrieves the data from logs and the SQL Database and displays the data to the user through the NSTI, (Nagios SNMP Trap Interface – A Perl/Python web application).

# Installing Nagios

This paper assumes you have Nagios installed. If you need installation instructions, see the [Nagios Quickstart Installation Guides](http://nagios.sourceforge.net/docs/3_0/quickstart.html).

# Net-SNMP

Net-SNMP is a suite of applications used to implement SNMP v1, SNMP v2c and SNMP v3 using both IPv4 and IPv6. The suite includes: 

* Command-line applications to:  
	* Retrieve information from an SNMP-capable device, either using single requests (snmpget, snmpgetnext), or multiple requests (snmpwalk, snmptable, snmpdelta),  
	* Manipulate configuration information on an SNMP-capable device (snmpset).
	* Retrieve a fixed collection of information from an SNMP-capable device (snmpdf, snmpnetstat, snmpstatus).
	* Convert between numerical and textual forms of MIB OIDs, and display MIB content and structure (snmptranslate). 
	* A graphical MIB browser (tkmib), using Tk/perl.

* A daemon application for receiving SNMP notifications (snmptrapd). Selected notifications can be logged (to syslog, the NT Event Log, or a plain text file), forwarded to another SNMP management system, or passed to an external application. 

* An extensible agent for responding to SNMP queries for management information (snmpd). This includes built-in support for a wide range of MIB information modules, and can be extended using dynamically loaded modules, external scripts and commands, and both the SNMP multiplexing (SMUX) and Agent Extensibility (AgentX) protocols. 

* A library for developing new SNMP applications, with both C and Perl APIs.

## Installing Net-SNMP (Using YUM or apt-get)

Net-SNMP and other utilities can be installed using yum or apt-get:

	$ sudo yum install net-snmp-utils net-snmp

Or,

	$ sudo apt-get install net-snmp-utils net-snmp

To make sure snmpd service starts automatically when Linux comes up, add snmpd service:

	$ sudo chkconfig --add snmpd

Continue with [Installing Net-SNMP-Perl Module](Installing Net-SNMP-Perl Module).

## Installing Net-SNMP (using Source)

Download source balls from http://net-snmp.sourceforge.net/download.html. Extract the package and move to the folder.

	$ cd net-snmp-5.7.2
	
Then, configure the package:

	$ sudo ./configure 

If necessary, edit include/net-snmp/net-snmp-config.h to customize settings such as log file generation etc.

Compile and install the package:

```
$ sudo make
$ sudo make test
$ sudo make install
```

## Installing Net-SNMP-Perl Module

Run the following to install the perl module for net-snmp:

	$ sudo yum install net-snmp-perl
Or, 

	$ sudo apt-get install net-snmp-perl

If you get an error "Can't locate Module/Build/Compat.pm in @INC contain...", install the following module to solve dependencies:

	$ sudo yum install perl-Module-Build
Or, 

    $ sudo  apt-get install perl-Module-Build


## Configure Net-SNMP

Use snmpconf to generate snmpd.conf, the configuration file for the snmpd service. In these instructions, we assume you are storing the .conf file in the following location: /etc/snmp/snmpd.conf. 

You can do this interactively using the following command:

	$ sudo snmpconf -g basic_setup

You can choose ports, debug levels, configuration directory etc.

Create the snmptrapd.conf file for the trap receiver. This can be done manually by creating the file "snmptrapd.conf" in the /etc/snmp/ folder or any other folder of your choice.

To point the snmptrapd service to the right configuration file, edit snmptrapd. The location of the snmptrapd file can be determined by using the "which" command.

	$ which snmptrapd

Open the file snmptrapd using vim as root:

	$ sudo vim /etc/init.d/snmptrapd

Change line number 29, where the OPTION variable is defined, to:

    OPTIONS="-On -Lsd -p /var/run/snmptrapd.pid -c /etc/snmp/snmptrapd.conf -Lf /home/foo/logs/snmptrapd.log"

In this statement, snmptrapd.pid is the process log, snmptrapd.conf is the configuration file created above, and snmptrapd.log is the log file. –On option is for stopping snmptrapd to change or translate the OIDs before giving the trap to a third party. This –On flag is required for AppDynamics Extensions.

Disable authorization by adding the following line to the snmptrapd.conf:

	disableAuthorization yes

Verify the installations by starting the services now:

	$ sudo service snmpd start
	$ sudo service snmptrapd start

Ensure that no errors occur during the boot.

# SNMPTT (SNMP Trap Translator)

SNMPTT (SNMP Trap Translator) is an SNMP trap handler written in Perl for use with the Net-SNMP / UCD-SNMP snmptrapd program (www.net-snmp.org). SNMPTT supports Linux, Unix and Windows.

## Installing SNMPTT

Download the source ball for snmptt from [http://sourceforge.net/projects/snmptt/](http://sourceforge.net/projects/snmptt/). Extract the package and cd to the directory of the exploded package:

    $ sudo tar -xzvf snmptt_1.3.tgz
    $ cd snmptt_1.3

The following Perl scripts are required as part of the snmptt installation:

*    snmpttconvert
*    snmptt
*    snmptthandler 
*    snmpttconvertmib

Copy them to /usr/sbin/ and give them execute permission:
 
```
$ sudo  cp  snmptt /usr/sbin/
$ sudo  chmod a+x /usr/sbin/snmptt
$ sudo  cp snmptthandler /usr/sbin/
$ sudo  chmod a+x /usr/sbin/snmptthandler
$ sudo  cp  snmpttconvert /usr/sbin/
$ sudo  chmod a+x /usr/sbin/snmpttconvert
$ sudo  cp  snmpttconvertmib /usr/sbin/
$ sudo  chmod a+x /usr/sbin/snmpttconvertmib
$ sudo  cp  snmptthandler /usr/sbin/
$ sudo  chmod a+x /usr/sbin/snmptthandler
```

Copy the snmptt setting file “snmptt.ini” to the directory where you stored the snmptrapd.conf file.
 
    $ cp  snmptt.ini  /etc/snmp/
 
Also create the log directory.

    $ sudo mkdir /var/log/snmptt

Copy the script to the init.d directory to register it as a system service.

	$ sudo chmod a+x snmptt.init.d
    $ sudo cp  snmptt.init.d  /etc/init.d/snmptt

## SMPTT.INI Settings

Edit the snmptt.ini to enable logging, debugging and MySQL connectivity, using the following options. Note: this configuration assumes the MySQL user name is ‘snmptt’, the password is ‘mytrap’, and the database name is snmptt.

```
mode = standalone
net_snmp_perl_enable = 1
net_snmp_perl_best_guess = 1
translate_log_trap_oid = 4
translate_value_oids = 1
translate_enterprise_oid_format = 1
translate_trap_oid_format = 1
mibs_environment = ALL
allow_unsafe_regex = 1
pid_file = /var/run/snmptt.pid
spool_directory = /var/spool/snmptt/
log_enable = 1
log_file = /var/log/snmptt/snmptt.log
log_system_enable = 1
log_system_file = /var/log/snmptt/snmpttsystem.log
unknown_trap_log_enable = 1
unknown_trap_log_file = /var/log/snmptt/snmpttunknown.log
mysql_dbi_enable = 1
mysql_dbi_host = localhost
mysql_dbi_port = 3306
mysql_dbi_database = snmptt
mysql_dbi_table = snmptt
mysql_dbi_table_unknown = snmptt_unknown
mysql_dbi_table_statistics = snmptt_statistics
mysql_dbi_username = snmptt
mysql_dbi_password = mytrap
DEBUGGING_FILE = /var/log/snmptt/snmptt.debug
DEBUGGING_FILE_HANDLER = /var/log/snmptt/snmptthandler.debug
```

Review and, if necessary, customize the values for these settings: 

```
pid_file
spool_directory
log_file
log_system_file
unknown_trap_log_file
mysql_dbi_host
mysql_dbi_port
mysql_dbi_database
mysql_dbi_table
mysql_dbi_username
mysql_dbi_password
DEBUGGING_FILE 
DEBUGGING_FILE_HANDLER 
```


## MySQL Schema for SMPTT

Install the latest version of mysql dB by using YUM or apt-get:

	$ sudo yum install mysql
Or,

    $ sudo apt-get install mysql

Create the MySQL user and DATABASE as specified in [SMPTT.INI Settings](SMPTT.INI Settings):
 
    $ sudo mysql

At the MySQL prompt, type the following to create the user, database and tables:

```
mysql> CREATE DATABASE snmptt;
mysql> use snmptt;
mysql> CREATE TABLE snmptt (
		id  INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		eventname  	VARCHAR(50),
		eventid  	VARCHAR(50),
		trapoid  	VARCHAR(100),
		enterprise  	VARCHAR(100),
		community 	 VARCHAR(20),
		hostname 	 VARCHAR(100),
		agentip  	 VARCHAR(16),
		category 	 VARCHAR(20),
		severity   	VARCHAR(20),
		uptime 		 VARCHAR(20),
		traptime 	VARCHAR(30),
		formatline 	VARCHAR(255));	
```
Note: To store the traptime as a real date/time (DATETIME data type), change 'traptime VARCHAR(30),' to 'traptime DATETIME,' and set date_time_format_sql in snmptt.ini to %Y-%m-%d %H:%M:%S.

Note: If you do not want the auto-incrementing id column, remove the 'id INT...' line. 

If you want to log unknown traps to a SQL table, create the snmptt_unknown table:

```
mysql> CREATE TABLE snmptt_unknown (
		trapoid VARCHAR(100),
		enterprise VARCHAR(100),
		community VARCHAR(20),
		hostname VARCHAR(100),
		agentip  VARCHAR(16),
		uptime  VARCHAR(20),	
		traptime VARCHAR(30),
		formatline VARCHAR(255));
```

Note: To store the traptime as a real date/time (DATETIME data type), change 'traptime VARCHAR(30),' to 'traptime DATETIME,' and set date_time_format_sql in snmptt.ini to %Y-%m-%d %H:%M:%S.

If you want to log statistics to a SQL table, create the snmptt_statistics table :

```
mysql> CREATE TABLE snmptt_statistics (
		stat_time VARCHAR(30),
		total_received BIGINT,
		total_translated BIGINT,
		total_ignored BIGINT,
		total_unknown BIGINT);
```

Note: To store the stat_time as a real date/time (DATETIME data type), change 'stat_time VARCHAR(30),' to 'stat_time DATETIME,' and set stat_time_format_sql in snmptt.ini to %Y-%m-%d %H:%M:%S.

Note: The variable lengths chosen above should be sufficient, but they may need to be increased depending on your environment.

To add a user account called 'snmptt' with a password of 'mytrap' for use by SNMPTT, use the following SQL statement:

    msql> GRANT ALL PRIVILEGES ON *.* TO 'snmptt'@'localhost' IDENTIFIED BY 'mytrap';

## Additional Perl Modules

The Perl modules DBI and DBI::mysql are also required. These can be installed by the following commands:

	$ sudo perl -MCPAN -e 'install DBI'
	$ sudo perl -MCPAN -e 'install DBD::mysql'


# Net-SNMP and SNMPTT Integration

To allow the snmptrapd to know of the trap translator snmptt, add the following line to the /etc/snmp/snmptrapd.conf:

	traphandle default /usr/sbin/snmptt

So now the snmptrapd.conf file will contain the following lines:

```
traphandle default /usr/sbin/snmptthandler
traphandle default /usr/sbin/snmptt
disableAuthorization yes
```

# SNMPTT and AppDynamics Integration


##Sending Traps from AppDynamics

Download the [snmptrapd-alerting-extension](http://appsphere.appdynamics.com/t5/Extensions/SNMP-Trap-Alerting-Extension/idi-p/825) from AppSphere and extract the zip file. The zip file contains jar and scripts to send the Traps. 

You also need to download the MIB file, so  the snmptt service can parse your trap. The sample MIB file could be found at:

[https://github.com/Appdynamics/snmptrap-alerting-extension/tree/master/src/main/custom/actions/send-snmp-trap](https://github.com/Appdynamics/snmptrap-alerting-extension/tree/master/src/main/custom/actions/send-snmp-trap)

To let snmptt know of traps from AppDynamics, you need to import APPD-CTLR-MIB.mib file from the snmptrapd-alerting-extension into the snmptt system:

	$ snmpttconvertmib --in=APPD-CTLR-MIB.mib --out=/etc/snmp/snmptt.conf.appdynamics --exec='/usr/local/nagios/libexec/submit_check_result $r TRAP 1' --net_snmp_perl
	
submit_check_result is a script installed when Nagios is installed. You may need to check its path and include it properly in the command. Edit the file “/etc/snmp/snmptt.conf.appdynamics” to have the full path to the MIB file in the header. The header should look like this:

```
#
#
#
#
MIB: APPD-CTLR-MIB (file:/home/foo/APPD-CTLR-MIB.mib) converted on Mon Sep 23 11:50:22 2013 using snmpttconvertmib v1.3
#
#
#
```
To enable the snmptt to parse the OIDs successfully, edit the OID expression to be a regular expression. The file /etc/snmp/snmptt.conf.appdynamics should have an entry like this:

	EVENT   event     .1.3.6.1.4.1.40684.1.1.1.500.1.     "Status Events"    Normal

Change this line to:

	EVENT   event     .1.3.6.1.4.1.40684.1.1.1.500.1.*     "Status Events"    Normal

This is important for the trap translation. 

Note: If you later modify the MIB file, for exacmple to specify custom levels or message formats, re-import the MIB into the SNMPTT system and make the above changes.

# Nagios SNMP Trap Interface Installation (NSTI)

Download [the latest NSTI](http://assets.nagios.com/downloads/nagiosti/downloads/nagiosti-head.tar.gz).

Extract the package and cd to the directory:

    $ tar xf nagiosti-head.tar.gz
    $ cd nagiosti

Edit the file functions.py to change the user and the user group, which is part of user group apache. Also properly set the value for the httpd’s configuration directory:

```
APACHE_CONF_DIR = '/etc/httpd/conf.d/'
USER  = 'nagios'
GROUP = 'nagios'
```

Edit the file “nsti/settings.py” to contain correct MySQL details:

```
DATABASES = {
	'default': {
	'ENGINE'    : 'django.db.backends.mysql',   # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
	'NAME'      : 'snmptt',  # Or path to database file if using sqlite3
	'USER'      : 'snmptt',  # Not used with sqlite3
	'PASSWORD'  : 'mytrap',  # Not used with sqlite3
	'HOST'      : '',        # Set to empty string for localhost. Not used with sqlite3
	'PORT'      : '',        # Set to empty string for default. Not used with sqlite3
	 }
}
```

Install the NSTI by issuing the following command:

	$ sudo python install.py
	

# Running Nagios NSTI with SNMPTT

Start the following services, or ensure that they are running, by using the following commands with one of the options given:

	$ sudo service httpd start/restart/status
	$ sudo service snmpd start/restart/status
	$ sudo service snmptrapd start/restart/status
	$ sudo service snmptt start/restart/status
	$ sudo service nagios start/restart/status
	$ sudo service nsti start/restart/status

After NSTI is up and running, you can view the interface by using the following URI:

	http://machine-ip/nsti

You should see something like this:

<br />
![](https://raw.github.com/Appdynamics/snmptrap-alerting-extension/master/integration_03.png)

You can now use the snmptrapd-alerting-extension downloaded earlier to send traps. For more details about this extension, see the [AppSphere Exchange](http://appsphere.appdynamics.com/t5/eXchange/SNMP-Trap-Alerting-Extension/idi-p/825).

# For more information

* [http://snmptt.sourceforge.net/docs/snmptt.shtml](http://snmptt.sourceforge.net/docs/snmptt.shtml)
* [http://www.snmptt.org/downloads.shtml](http://www.snmptt.org/downloads.shtml)
* [http://assets.nagios.com/downloads/nagiosti/documentation/](http://assets.nagios.com/downloads/nagiosti/documentation/)
* [http://skipperkongen.dk/2011/10/27/running-nagios-on-ec2/](http://skipperkongen.dk/2011/10/27/running-nagios-on-ec2/)
* [http://xavier.dusart.free.fr/nagios/en/snmptraps.html](http://xavier.dusart.free.fr/nagios/en/snmptraps.html)
* [http://serverfault.com/questions/412834/cant-locate-config-inifiles-pm-in-inc-inc-contains](http://serverfault.com/questions/412834/cant-locate-config-inifiles-pm-in-inc-inc-contains)
* [http://stackoverflow.com/questions/9947497/i-am-getting-invalid-command-wsgiscriptalias-error-while-starting-apache](http://stackoverflow.com/questions/9947497/i-am-getting-invalid-command-wsgiscriptalias-error-while-starting-apache)
* [http://hyper-choi.blogspot.in/2012/12/nagios-snmp-trap-part-1-snmptt.html](http://hyper-choi.blogspot.in/2012/12/nagios-snmp-trap-part-1-snmptt.html)


