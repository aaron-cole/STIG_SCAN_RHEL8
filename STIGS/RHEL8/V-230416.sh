#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230416"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230416r627750_rule"
STIGID="RHEL-08-030230"
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

if [ "$(uname -i)" == "x86_64" ]; then
 rules="b64 b32"
else
 rules="b32"
fi

for f in $rules; do
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S.*[ ,]fsetxattr[, ].*-F auid>=1000 -F auid!=-1" >> $Results; then
  echo "$f >1000 rule does not exist" >> $Results 
  ((scorecheck+=1))
 fi
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S.*[ ,]fsetxattr[, ].*-F auid=0" >> $Results; then
  echo "$f =0 rule does not exist" >> $Results 
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
