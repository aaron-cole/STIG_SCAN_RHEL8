#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230401"
GrpTitle="SRG-OS-000057-GPOS-00027"
RuleID="SV-230401r599732_rule"
STIGID="RHEL-08-030120"
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

auditlogfile="$(grep "^log_file =" /etc/audit/auditd.conf | awk '{print $3}')"

if [ -f $auditlogfile ]; then
 ls -ld $(dirname $auditlogfile) >> $Results
 if [ "$(stat -Lc %a $(dirname $auditlogfile))" -eq "700" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "$auditlogfile from /etc/audit/auditd.conf does not exist" >> $Results 
 echo "Fail" >> $Results
fi
