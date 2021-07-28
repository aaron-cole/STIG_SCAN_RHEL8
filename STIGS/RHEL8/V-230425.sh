#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230425"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230425r627750_rule"
STIGID="RHEL-08-030302"
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
scorecheck=0

for f in b64 b32; do
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S.*[ ,]mount[, ].*-F auid>=1000 -F auid!=-1" >> $Results; then
  echo "$f mount rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
