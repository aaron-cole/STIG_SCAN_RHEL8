#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

#STIG Identification
GrpID="V-230546"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230546r599732_rule"
STIGID="RHEL-08-040282"
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

chkfiles="$(grep "^kernel.yama.ptrace_scope" /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":"| sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^kernel.yama.ptrace_scope" "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^kernel.yama.ptrace_scope" "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 1 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^kernel.yama.ptrace_scope" "$chkfile")" >> $Results
   else
    echo "Fail - Setting not found in $chkfile" >> $Results
   fi
  done
 else
  echo "Fail - $chkfile - too many entries" >> $Results
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl kernel.yama.ptrace_scope | awk -v opf="$Results" '/^kernel.yama.ptrace_scope/ {
	if($3 == 1) {
	 print "Pass - Setting Found in runtime -" $0 >> opf
	 } else {
	 print "Fail - Setting Not Found in runtime -" $0 >> opf
	 }
}'

if grep "Fail" $Results >> /dev/null; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
