#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230479"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-230479r627750_rule"
STIGID="RHEL-08-030690"
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

if grep "^\*\.\*.*@" /etc/rsyslog.conf | grep -v "^#" >> $Results; then 
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
