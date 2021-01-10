#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230525"
GrpTitle="SRG-OS-000420-GPOS-00186"
RuleID="SV-230525r599732_rule"
STIGID="RHEL-08-040150"
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

grep "^FirewallBackend=" /etc/firewalld/firewalld.conf >> $Results

if [ "$(grep "^FirewallBackend=" /etc/firewalld/firewalld.conf | awk -F= '{print $2}')" == "nftables" ]; then
 echo "Pass" >> $Results
else
 echo "not defined" >> $Results
 echo "Fail" >> $Results
fi
