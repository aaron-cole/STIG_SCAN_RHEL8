#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230229"
GrpTitle="SRG-OS-000066-GPOS-00034"
RuleID="SV-230229r627750_rule"
STIGID="RHEL-08-010090"
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

if [ -e /etc/sssd/pki/sssd_auth_ca_db.pem ]; then
 egrep "subect=|issuer=" /etc/sssd/pki/sssd_auth_ca_db.pem >> $Results
 if egrep "subect=|issuer=" /etc/sssd/pki/sssd_auth_ca_db.pem | egrep -v "CN = DoD|CN = DOD" >> /dev/null; then
  echo "Fail" >> $Results
 else
  echo "Pass" >> $Results
 fi
else
 echo "/etc/sssd/pki/sssd_auth_ca_db.pem not found" >> $Results
 echo "Fail" >> $Results
fi
