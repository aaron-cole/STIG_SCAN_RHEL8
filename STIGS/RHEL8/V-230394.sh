#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230394"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-230394r627750_rule"
STIGID="RHEL-08-030062"
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

if grep "^name_format =" /etc/audit/auditd.conf | egrep -vi "none|user" | egrep -i "hostname|fqdn|numeric" >> $Results; then
 echo "Pass" >> $Results
else
 echo "name_format not set" >> $Results
 echo "Fail" >> $Results
fi
