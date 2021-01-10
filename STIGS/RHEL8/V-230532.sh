#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The debug-shell requires no authentication and provides root privileges to anyone who has physical access to the machine.  While this feature is disabled by default, masking it adds an additional layer of assurance that it will not be enabled via a dependency in systemd.  This also prevents attackers with physical access from trivially bypassing security on the machine through valid troubleshooting configurations and gaining root access when the system is rebooted.

#STIG Identification
GrpID="V-230532"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230532r599815_rule"
STIGID="RHEL-08-040180"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

echo "$(systemctl status debug-shell.service)" >> $Results

if [ "$(systemctl is-enabled debug-shell.service)" == "masked" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
