#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230487"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-230487r599732_rule"
STIGID="RHEL-08-040000"
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

if rpm -q telnet-server >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
