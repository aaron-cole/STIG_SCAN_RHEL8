#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230552"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230552r599732_rule"
STIGID="RHEL-08-040310"
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

if ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Tripwire is installed" >> $Results
 echo "Pass" >> $Results 
elif rpm -q aide >> $Results; then
 rules="$(grep "^/" /etc/aide.conf | grep -v "^#" | awk '{print $2}' | grep -v "^LOG" | sort | uniq)"
 aclrules="$(grep "acl" /etc/aide.conf | grep -v "^#" | awk '{print $1}')"
 for rule in $rules; do
  if grep "^$rule" /etc/aide.conf | grep acl >> $Results; then 
    echo "" >> /dev/null
  else
   if [ "$(for aclrule in $aclrules; do if [ "$rule" == "$aclrule" ]; then echo "" >> /dev/null; else if grep "^$rule" /etc/aide.conf | grep $aclrule; then echo "" >> /dev/null;fi;fi;done)" ]; then
    echo "" >> /dev/null
   else
    echo "$rule does not include ACL" >> $Results
	((scorecheck+=1))
   fi	
  fi
 done
else
 echo "Aide not installed" >> $Results
 ((scorecheck+=1)) 
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
