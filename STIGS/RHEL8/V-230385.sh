#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

#STIG Identification
GrpID="V-230385"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230385r627750_rule"
STIGID="RHEL-08-020353"
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

filestocheck="/etc/bashrc /etc/csh.cshrc"
for filetocheck in $filestocheck; do
 if [ -e $filetocheck ]; then
  for linefound in $(grep "umask" /etc/bashrc | grep -v "#" | awk '{print $2}'); do 
   echo "UMASK $linefound" >> $Results
   if [ "$linefound" != "077" ]; then 
    ((scorecheck+=1))
   fi
  done
 else
  echo "$filetocheck doesn't exist" >> $Results
 fi
done

if [ "$scorecheck" != 0 ]
then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
