#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230504"
GrpTitle="SRG-OS-000297-GPOS-00115"
RuleID="SV-230504r599732_rule"
STIGID="RHEL-08-040090"
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

firewall-cmd --state >> $Results
if [ "$(firewall-cmd --state)" == "running" ]; then
 firewall_active_zones="$(firewall-cmd --get-active-zones | grep -v "interfaces:")"
 for firewall_active_zone in $firewall_active_zones; do
  firewall-cmd --info-zone=$firewall_active_zone | egrep "^$firewall_active_zone|target:" >> $Results
  if [ "$(firewall-cmd --info-zone=$firewall_active_zone | grep "target:" | awk '{print $2}')" == "DROP" ]; then
   echo "Pass" >> $Results
   echo "" >> $Results
  else
   echo "Fail" >> $Results
   echo "" >> $Results   
   ((scorecheck+=1))
  fi
 done
else
 echo "Firewalld is not running" >> $Results
 ((scorecheck+=1))
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
