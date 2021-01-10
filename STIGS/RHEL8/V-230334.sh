#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230334"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230334r599829_rule"
STIGID="RHEL-08-020012"
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

rhel8version="$(rpm -qi redhat-release | grep "^Version" | awk '{print $3}')"

if (( $(echo "$rhel8version > 8.1" | bc -l) )); then
 echo "RHEL Version is $rhel8version" >> $Results
 echo "NA" >> $Results
else
 echo "Manual Check" >> $Results
 echo "Fail" >> $Results
fi
 