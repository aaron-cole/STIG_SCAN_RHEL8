#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230482"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-230482r627750_rule"
STIGID="RHEL-08-030720"
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

if grep '$ActionSendStreamDriverAuthMode x509/name' /etc/rsyslog.conf | grep -v "^#" >> $Results; then 
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
