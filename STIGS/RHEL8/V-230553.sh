#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used, unless approved and documented.

#STIG Identification
GrpID="V-230553"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230553r646886_rule"
STIGID="RHEL-08-040320"
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

systemctl get-default >> $Results

if [ $(systemctl get-default) = "multi-user.target" ]; then
 if rpm -q xorg-x11-server-common >> $Results; then
  echo "Fail" >> $Results
 else 
  echo "Pass" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
