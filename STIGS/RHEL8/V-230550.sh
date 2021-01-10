#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.

#STIG Identification
GrpID="V-230550"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230550r599732_rule"
STIGID="RHEL-08-040290"
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

if rpm -q postfix >> $Results; then
 postconf -n smtpd_client_restrictions >> $Results
 if [[ "$(postconf -n smtpd_client_restrictions)" == "smtpd_client_restrictions = permit_mynetworks,reject" ]]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "NA" >> $Results
fi
