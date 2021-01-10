#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230506"
GrpTitle="SRG-OS-000299-GPOS-00117"
RuleID="SV-230506r599732_rule"
STIGID="RHEL-08-040110"
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

if  dmidecode | grep "Product Name" | grep "VMware" >> $Results; then
 echo "Wireless cards do not exist on Virtual Machines" >> $Results
 echo "NA" >> $Results
else
 if ip link | grep ": wl" >> $Results; then
  echo "Fail" >> $Results
 else
  echo "No Wireless interface found" >> $Results 
  echo "Pass" >> $Results
 fi
fi
