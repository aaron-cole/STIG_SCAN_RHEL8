#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.

#STIG Identification
GrpID="V-230281"
GrpTitle="SRG-OS-000437-GPOS-00194"
RuleID="SV-230281r599732_rule"
STIGID="RHEL-08-010440"
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

if [ -f /etc/dnf/dnf.conf ] && [ "$(grep "^clean_requirements_on_remove" /etc/dnf/dnf.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^clean_requirements_on_remove/ {
	if($2 == 1 || $2 == "True") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/dnf/dnf.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
