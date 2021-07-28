#!/bin/sh
###################################################
#
# STIG_SCAN.sh
#
# Created by - Aaron Cole
# Version 1.0 
# Dated 5/31/2017
# 
#
# Synopsis - SHELL Script to run DISA STIGS 
#	     against a machine and verify security
#            settings.
###################################################

####Variables####
CWD="$(echo $PWD)"
chownuser="$(echo $SUDO_USER)"
TempDIR="./Results"
ReportsDIR="./Reports"
STIGDIR="./STIGS"
RunTime="$(date +%F_%s)"
mydate="$(date +%F)"
servername="$(hostname)"
rfoldname="$servername-$RunTime"
CRDIR="$ReportsDIR/$rfoldname"
xccdffile="$rfoldname.xccdf.xml"
cklfile="$CRDIR/$servername-RHEL8_V1R3_$mydate.ckl"
TempCKLSTIG="$TempDIR/CKLprocessing"
starttime=$(date)

####Start of Functions####

fnusage()
{
echo "Usage {SCRIPT NAME} [option] [option] ....

Options are not needed to run a scan.
By Default the CKL file will be created.

Options
 -h | --help 		-displays this message
 -d | --debug		-will not delete any files,
					 enabled verbose and xccdf
 -r | --reports		-Assumes STIG Checks are completed and will
					 skip checks and create both the xccdf import
					 and CKL file if results are in the correct
					 location
 -s | --cklonly		-Same as -r, but will only create CKL file
 -t | --xccdfonly	-Same as -r, but will only create xccdf file
 -v | --verbose		-enables more info during running of script
 -x | --xccdf		-enables the creation of the xccdf import
					 for STIGViewer
Examples:
./STIG_SCAN.sh -d         Does not delete any temp files created by 
                          This script. 
"
}

####Start of Script####

echo "Started @ $starttime"

#Check if running as root
if [ "$(id -u)" != "0" ]; then
	echo "This has to be run as root" 1>&2
	exit 1
fi

#Set variables
argd=0
argr=0
argv=0
argx=0
arge=0

##Checking Command-Line Args####
for arg in "$@"; do 
	case $1 in
		-h | --help )							
					fnusage
					exit
					;;
		-d | --debug )							
					argd=1
					argv=1
					argx=1
					arge=1
					shift
					;;
		-r | --reports )
					argr=1
					argx=1
					arge=1
					shift
					;;
		-s | --cklonly )
					argr=1
					shift
					;;					 
		-t | --xccdfonly )
					argr=1
					argx=1
					shift
					;;					
		-v | --verbose )
					argv=1
					shift
					;;
		-x | --xccdf )
					argx=1
					shift
					;;
		* )							
					shift
					;;
	esac
done

if [ $argr = 1 ]; then
 if [ ! -d $TempDIR ]; then
  echo "Results Directory Not Found"
  echo "Exiting"
  exit 1
 fi
fi

#Create TempDIR if it doesn't exist
if [ ! -d $TempDIR ]; then
 mkdir $TempDIR
fi

#Check OS for right STIGs
if grep "8\." /etc/redhat-release >> /dev/null; then
 OS="RHEL8"
 chmod +x $STIGDIR/$OS/*
 BLANKCKL="$STIGDIR/CKL_Templates/blank_rhel8.ckl"
 ipaddress="$(hostname -i)"
 macaddress="$(ip addr | grep -B1 "$ipaddress" | grep -v "inet" | awk '{print $2}' )"
else
 exit
fi

#PreStage
echo "Performing PreStage"

if [ -e "$STIGDIR/$OS/prestage.sh" ] && [ $argr = 0 ]; then
 $STIGDIR/$OS/prestage.sh
fi

if [ "$OS" = "RHEL7" ]; then
 if [ $argr = 1 ] && [ -e $TempDIR/RPMVA_status ]; then
  echo "Using already completed file in $TempDIR/RPMVA_status"
 else
  if [ $argv = 1 ]; then
   echo "Running rpm -Va command - this could take alittle bit"
   rpm -Va --noconfig >> $TempDIR/RPMVA_status 2>>/dev/null
  else
   rpm -Va --noconfig >> $TempDIR/RPMVA_status 2>>/dev/null
  fi
 fi
fi

echo
echo "Prestage Complete"
echo

#SKIP checks if Reports only enabled
if [ $argr = 0 ];then

##Start Checks##
echo "Starting Checks"
if [ $argv = 1 ]; then
 echo $(date)
##Runs Each STIG in ./STIGs folder
 for stig in $STIGDIR/$OS/V*.sh; do
  echo "Checking $stig"
  $stig
 done
else
 for stig in $STIGDIR/$OS/V*.sh; do
  $stig
 done
fi 

#Probably need to check if result files are there?
else
 echo "Using already created check files"
fi
##############Reports#####################
if [ ! -d $CRDIR ]; then
 mkdir -p $CRDIR
fi

#Create xccdf xml
if [ $argx = 1 ]; then
echo "Creating xccdf importable STIGviewer file" 
echo $(date)
#Header
cat <<EOF >> $CRDIR/$xccdffile
<?xml version="1.0" encoding="UTF-8"?>
<cdf:Benchmark style="SCAP_1.1" resolved="1" id="RHEL_6_STIG" xsi:schemaLocation="http://checklists.nist.gov/xccdf/1.1 http://nvd.nist.gov/schema/xccdf-1.1.4.xsd http://cpe.mitre.org/dictionary/2.0 http://scap.nist.gov/schema/cpe/2.2/cpe-dictionary_2.2.xsd" xmlns:cdf="http://checklists.nist.gov/xccdf/1.1" xmlns:cpe="http://cpe.mitre.org/dictionary/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xhtml="http://www.w3.org/1999/xhtml">
<cdf:TestResult>
<cdf:target>$(hostname)</cdf:target>
<cdf:target-address>$ipaddress</cdf:target-address>
<cdf:target-facts>
<cdf:fact name="urn:scap:fact:asset:identifier:hostname" type="string">$(hostname)</cdf:fact>
<cdf:fact name="urn:scap:fact:asset:identifier:ipv4" type="string">$ipaddress</cdf:fact>
<cdf:fact name="urn:scap:fact:asset:identifier:mac" type="string">$macaddress</cdf:fact>
</cdf:target-facts>
EOF

#Start filling in findings
for i in $TempDIR/V*; do
statusdata="$(tail -n -1 $i)"

if [ "$statusdata" = "Pass" ]; then
 stigresult="pass"
elif [ "$statusdata" = "Fail" ]; then
 stigresult="fail"
else
 stigresult=""
fi

cat <<EOF >> $CRDIR/$xccdffile
<cdf:rule-result version="NA" time="NA" idref="$(sed -n "3p" $i)" weight="10.0" severity="NA">
<cdf:result>$stigresult</cdf:result><cdf:ident /><cdf:check /></cdf:rule-result>
EOF

done
cat <<EOF >> $CRDIR/$xccdffile
</cdf:TestResult>
</cdf:Benchmark>
EOF
echo "XCCDF is done"
fi

###Creating CKL file
if [ ! -e $BLANKCKL ] || [ -z $BLANKCKL ]; then
 echo "Blank CKL Template not found"
else
echo "Creating CKL file" 
fqdn="$(awk '/'"$ipaddress"'/ {print $2}' /etc/hosts)"
echo $(date)
while IFS= read -r line; do
 case "$line" in
 *HOST_NAME*)	echo "$line" | sed 's/<HOST_NAME>/<HOST_NAME>'"$(hostname)"'/' >> $cklfile;;				
 *HOST_IP*) 	echo "$line" | sed 's/<HOST_IP>/<HOST_IP>'"$ipaddress"'/' >> $cklfile;;
 *HOST_MAC*) 	echo "$line" | sed 's/<HOST_MAC>/<HOST_MAC>'"$macaddress"'/' >> $cklfile;;
 *HOST_FQDN*) 	echo "$line" | sed 's/<HOST_FQDN>/<HOST_FQDN>'"$fqdn"'/' >> $cklfile;;
 
 *\>V-*)	Vline="$(echo "$line" | sed 's/^.*>V/V/' | sed 's/<.*$//')"
			echo "$Vline" > $TempCKLSTIG
			echo "$line" >> $cklfile;;
				
 *Not_Reviewed*)	STIGfile="$(grep ^V $TempCKLSTIG)"
					FindingData="$(tail -n -1 "$TempDIR/$STIGfile")"
					case $FindingData in
						Pass)	#echo "$line" | awk '{ sub("Not_Reviewed", "NotAFinding")};{print}' >> $cklfile;;
								echo "                <STATUS>NotAFinding</STATUS>" >> $cklfile;;
						Fail)	#echo "$line" | awk '{ sub("Not_Reviewed", "Open")};{print}' >> $cklfile;;
								echo "                <STATUS>Open</STATUS>" >> $cklfile;;
						NA)		#echo "$line" | awk '{ sub("Not_Reviewed", "Not_Applicable")};{print}' >> $cklfile;;
								echo "                <STATUS>Not_Applicable</STATUS>" >> $cklfile;;
						*)		echo "$line" >> $cklfile;;
					esac;;
					
 *FINDING_DETAILS*)	if [ "$(wc -l < $TempDIR/$STIGfile)" = "5" ]; then
					 echo "$line" >> $cklfile
					else
					 case $FindingData in
						Fail)	#echo "$line" | sed 's/></>'"$(tail -n +5 $TempDIR/$STIGfile |head -n -1)"'</' >> $cklfile;;
#								echo "                <FINDING_DETAILS>$(tail -n +5 $TempDIR/$STIGfile | head -n -1)</FINDING_DETAILS>" >> $cklfile;;
#								echo "                <FINDING_DETAILS>$(tail -n +5 $TempDIR/$STIGfile | sed '$d')</FINDING_DETAILS>" >> $cklfile;;
								echo "                <FINDING_DETAILS>$(tail -n +5 $TempDIR/$STIGfile | sed '$d' | sed 's/<</\&lt;\&lt;/g' | sed 's/1>>/1\&gt;\&gt;/g' | sed 's/2>\&1/2\&gt;\&amp;1/g')</FINDING_DETAILS>" >> $cklfile;;
						*)		echo "$line" >> $cklfile;;
					 esac
					fi;;
 *COMMENTS*)	if [ "$(wc -l < $TempDIR/$STIGfile)" = "5" ]; then
				 echo "$line" >> $cklfile
				else
				 case $FindingData in
					Pass|NA)	#echo "$line" | sed 's/></>'"$(tail -n +5 $TempDIR/$STIGfile |head -n -1)"'</' >> $cklfile;;
#								echo "                <COMMENTS>$(tail -n +5 $TempDIR/$STIGfile | head -n -1)</COMMENTS>" >> $cklfile;;
								echo "                <COMMENTS>$(tail -n +5 $TempDIR/$STIGfile |  sed '$d' | sed 's/<</\&lt;\&lt;/g' | sed 's/1>>/1\&gt;\&gt;/g' | sed 's/2>\&1/2\&gt;\&amp;1/g')</COMMENTS>" >> $cklfile;;
					*)		echo "$line" >> $cklfile;;
				 esac
				fi;;	
					
 *)  echo "$line" >> $cklfile;;
				
 esac
 
done <$BLANKCKL
echo "CKL File is done"
fi
#############End of Reports#############
###################################################
##########Remove Created files##########
####If Debug is not enabled####
if [ $arge = 0 ]; then
	rm -rf $TempDIR
fi
####End of removing Result Files ####
echo "Started @ $starttime"
echo "Ended @" $(date)
chown -R $chownuser $CWD
if [ $argx = 1 ]; then
 echo "xccdf File is $CRDIR/$xccdffile"
fi
echo "CKL File is $cklfile"
