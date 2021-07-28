#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230239"
GrpTitle="SRG-OS-000120-GPOS-00061"
RuleID="SV-230239r646864_rule"
STIGID="RHEL-08-010162"
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

if rpm -q krb5-workstation >> $Results; then
 rpm -qi krb5-workstation | grep "^Version" >> $Results
 if [ "$(rpm -qi krb5-workstation | grep "^Version" | awk '{print $3}' | cut -f 2 -d".")" = "17-18")" ] ||  [ "$(rpm -qi krb5-workstation | grep "^Version" | awk '{print $3}' | cut -f 2 -d".")" = "18")" ]; then
  echo "NA" >> $Results
 else
  echo "Fail" >> $Results
 fi
else 
 echo "Pass" >> $Results
fi
