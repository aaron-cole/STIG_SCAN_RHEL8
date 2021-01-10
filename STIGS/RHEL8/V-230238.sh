#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230238"
GrpTitle="SRG-OS-000120-GPOS-00061"
RuleID="SV-230238r599732_rule"
STIGID="RHEL-08-010161"
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

find /etc -type f -name "*.keytab" 2>>/dev/null >> $Results

if [ "$(find /etc -type f -name "*.keytab" 2>>/dev/null )" ]; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
