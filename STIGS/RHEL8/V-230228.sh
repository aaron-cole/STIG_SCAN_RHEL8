#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230228"
GrpTitle="SRG-OS-000032-GPOS-00013"
RuleID="SV-230228r599732_rule"
STIGID="RHEL-08-010070"
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
itemstocheck="auth authpriv daemon"

for itemtocheck in $itemstocheck; do
 if grep "^$itemtocheck\.\*" /etc/rsyslog.conf >> $Results; then
  echo "" >> /dev/null
 else
  echo "$itemtocheck logging not found" >> $Results 
  ((scorecheck+=1))
 fi
done

 if [ "$scorecheck" != 0 ]; then
  echo "Fail" >> $Results 
 else 
  echo "Pass" >> $Results
 fi
fi
