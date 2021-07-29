#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230238"
GrpTitle="SRG-OS-000120-GPOS-00061"
RuleID="SV-230238r646862_rule"
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
fncheck () {
find /etc -type f -name "*.keytab" 2>>/dev/null >> $Results
 if [ "$(find /etc -type f -name "*.keytab" 2>>/dev/null )" ]; then
  echo "Fail" >> $Results
 else
  echo "Nothing Found" >> $Results
  echo "Pass" >> $Results
 fi
}

if rpm -qi krb5-server >> $Results; then
 if [ "$(rpm -qi krb5-server | grep "^Version" | awk '{print $3}' | cut -f 2 -d".")" = "17-18" ] ||  [ "$(rpm -qi krb5-server | grep "^Version" | awk '{print $3}' | cut -f 2 -d".")" = "18" ]; then
  echo "NA" >> $Results
 else
  fncheck
 fi
elif rpm -qi krb5-workstation >> $Results; then
 if [ "$(rpm -qi krb5-workstation | grep "^Version" | awk '{print $3}' | cut -f 2 -d".")" = "17-18" ] ||  [ "$(rpm -qi krb5-workstation | grep "^Version" | awk '{print $3}' | cut -f 2 -d".")" = "18" ]; then
  echo "NA" >> $Results
 else
  fncheck
 fi
else
 fncheck 
fi
