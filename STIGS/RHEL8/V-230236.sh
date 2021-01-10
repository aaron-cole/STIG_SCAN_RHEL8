#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the system does not require valid root authentication before it boots into emergency or rescue mode, anyone who invokes emergency or rescue mode is granted privileged access to all files on the system.

#STIG Identification
GrpID="V-230236"
GrpTitle="SRG-OS-000080-GPOS-00048"
RuleID="SV-230236r599732_rule"
STIGID="RHEL-08-010151"
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

if grep "^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue" /usr/lib/systemd/system/rescue.service >> $Results; then
 echo "Pass" >> $Results
else
 grep "^ExecStart=" /usr/lib/systemd/system/rescue.service >> $Results
 echo "Fail" >> $Results
fi
