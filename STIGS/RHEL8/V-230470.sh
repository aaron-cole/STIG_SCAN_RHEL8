#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230470"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230470r744006_rule"
STIGID="RHEL-08-030603"
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

if [ -f /etc/usbguard/usbguard-daemon.conf ] && [ "$(grep "^AuditBackend=" /etc/usbguard/usbguard-daemon.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^AuditBackend=/ {
	if($2 == "LinuxAudit") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/usbguard/usbguard-daemon.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
