#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230386"
GrpTitle="SRG-OS-000326-GPOS-00126"
RuleID="SV-230386r599732_rule"
STIGID="RHEL-08-030000"
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
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S execve -C uid!=euid -F euid=0" >> $Results; then
  echo "$f uid rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S execve -C gid!=egid -F egid=0" >> $Results; then
  echo "$f gid rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
