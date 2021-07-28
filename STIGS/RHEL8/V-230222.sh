#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.

#STIG Identification
GrpID="V-230222"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230222r627750_rule"
STIGID="RHEL-08-010010"
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

thismonth=$(date +%b)
lastmonth=$(date +"%b" -d "-1 month")
if rpm -qa -last | grep $(date +%Y) | egrep "$lastmonth|$thismonth" >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
