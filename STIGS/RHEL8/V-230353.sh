#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230353"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-230353r627750_rule"
STIGID="RHEL-08-020070"
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

if [ -f /etc/tmux.conf ] && [ "$(grep "^set -g lock-after-time" /etc/tmux.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^set -g lock-after-time/ {
	if($4 <= 900) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/tmux.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
