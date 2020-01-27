#!/bin/bash

#--------------------General notes/checks for the script--------------------
#Make sure you have a reliable Internet conection before running this script
wget -q --spider http://google.com
if [ $? -ne 0 ];
then
    echo "You are offline."
    echo "Please make sure that you have a reliable Internet connection before running this script."
    exit
fi

#Make sure you are running this script as a superuser i.e. as 'root'.
if [[ $EUID -ne 0 ]];
then
   echo "Please run this script as root."
   exit
fi

#make sure debian build tools are installed
which dpkg-deb fakeroot dpkg-scanpackages debsigs
if [ $? -ne 0 ];
then
    echo "dpkg-deb, fakeroot, dpkg-scanpackages and debsigs are not in your PATH."
    exit
#else
    #echo "dpkg-deb, fakeroot, dpkg-scanpackages and debsigs are in your PATH."
 #   echo "Sane configuration found, starting script."
fi

echo "Setting up the environment..."
#echo "Checking the openssl version..."
OPENSSLVERSION=`openssl version -v`
if echo "$OPENSSLVERSION" | grep -q "OpenSSL 1.0."; 
then
    echo "OpenSSL version is good."
else
    echo "OpenSSL version is not good."
    exit
fi

osg-koji setup

#01/27/2020 - removing OSG Security team signatures
#gpg --edit-key 7FD42669 trust quit

#echo "Verifing the key id value for OSG" 
#if gpg --list-keys | grep -q "security@opensciencegrid.org";
#then 
#    echo "Required key for OSG is present."
#else 
#    echo "Required key for OSG is not present."
#    exit
    #THIS NEEDS UNCOMMENTED FOR PROD
#fi

gpg --recv-key 3CDBBC71
gpg --check-sigs 3CDBBC71

#01/27/2020 - removing OSG Security team signatures
#while true; do
#    gpg --default-key $OSGSECKEYID --lsign-key 3CDBBC71
#    if [ $? -ne 0 ];
#    then
#        echo "Cross-signing failed, retrying."
#    else
#        break
#    fi
#done

#--------------------General notes/checks completed--------------------



#--------------------Variable declaration--------------------
#Define variable for OSG PGP key
#export OSGSECKEYID=7FD42669

#Set IGTF_CERTS_VERSION according to the release indicated
echo "Enter the IGTF cert version according to the release indicated:"
while true; do
    read IGTF_CERTS_VERSION
    if [[ $IGTF_CERTS_VERSION =~ ^[0-9.]+$ ]];
    then
        export IGTF_CERTS_VERSION
        break
    else
    echo "Please enter a valid IGTF cert version."
    fi
done

#Set the OSG certificate distribution version 
echo "Enter our IGTF cert version i.e. n.xIGTFNEW:"
while true; do
    read OUR_CERTS_VERSION
    if [[ $OUR_CERTS_VERSION =~ ^[0-9]+[.][0-9]+(IGTFNEW)$ ]];
    then
        export OUR_CERTS_VERSION
        break
    else
        echo "Please enter a valid our IGTF cert version i.e. n.xIGTFNEW."
    fi
done

#[05/28/19]echo "Enter your user name for VDT machine i.e. for library.cs.wisc.edu:"
echo "Enter your user name for VDT machine i.e. for moria.cs.wisc.edu:"
while true; do
    read USERNAME_VDT
    if [[ $USERNAME_VDT =~ ^[a-z.0-9]+$ ]];
    then
        export USERNAME_VDT
        break
    else
        echo "Please enter a valid user name for VDT machine i.e. for moria.cs.wisc.edu."
    fi
done

echo "What is the Jira ticket number i.e. SOFTWARE-XXXX?"
while true; do
    read JIRA_TICKET
    if [[ $JIRA_TICKET =~ ^(SOFTWARE)[-][0-9]+$ ]];
    then
        export JIRA_TICKET
        break
    else
        echo "Please enter a valid Jira ticket number i.e. SOFTWARE-XXXX."
    fi
done

#Set the variable n.nn
export NNN=$IGTF_CERTS_VERSION

#Set the variable l.ll
export LLL=$(echo "$OUR_CERTS_VERSION" | grep -o -E '[0-9]+\.[0-9]+')

#Set the previous version of OUR_CERTS_VERSION for IGTF
export PREVIOUS_IGTFNEW=`echo "$LLL - 0.01" | bc -l`IGTFNEW
#--------------------Variable declaration completed--------------------



#--------------------Prepare for multiple caches--------------------
#--------------------Process for IGTF CA i.e. IGTFNEW--------------------
echo "Preparing for IGTFNEW..."
#Change to an empty working directory and set $CAWORKDIR to the path
export CAWORKDIR=`mktemp -d`

#Checkout or update the OSG svn directories
cd /root/certs/trunk/cadist/CA-Certificates-Base
svn update --username $USERNAME_VDT 
export CABASEDIR=/root/certs/trunk/cadist/CA-Certificates-Base

#Create a new distribution directory for the release
mkdir -p "$OUR_CERTS_VERSION/certificates"
export CADIST=$CABASEDIR/$OUR_CERTS_VERSION/certificates

#Download the new IGTF distribution tarball (and PGP signature) from http://dist.eugridpma.info/distribution/igtf/current/
cd "$CAWORKDIR"
wget "http://dist.eugridpma.info/distribution/igtf/current/igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz"
wget "http://dist.eugridpma.info/distribution/igtf/current/igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz.asc"

#Verify the PGP signature on the tarball
gpg --verify "igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz.asc"
if [ $? -ne 0 ];
then
    echo "PGP signature verification failed."
    exit
else
    echo "Signature is good."
fi

#Unpack the certificates
tar xzf "igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz"

#Select the CAs and install to temporary location
cd "igtf-policy-installation-bundle-$IGTF_CERTS_VERSION"
./configure --prefix="$CADIST" --with-profile=classic --with-profile=mics --with-profile=slcs --with-profile=iota
make install

#Compare differences with previous version
#Make sure appropriate extra CA files from $CABASEDIR/non-igtf-certificates are included or removed from the distribution directory $CADIST
cd "$CADIST"
for ca in * ; do echo "$ca"; diff "$ca" "$CABASEDIR/$PREVIOUS_IGTFNEW/certificates"; done
for ca in "$CABASEDIR/$PREVIOUS_IGTFNEW/certificates"/* ; do echo "$ca"; diff "$ca" . ; done

#Generate the index files 
cd "$CABASEDIR"
OPENSSL_LOCATION=`which openssl`
./mk-index.pl --version "$OUR_CERTS_VERSION" --dir "$CADIST" --out "$CADIST/INDEX" --ssl1 "$OPENSSL_LOCATION" -format 1 --style new
TOTAL_CA=$(./mk-index.pl --version "$OUR_CERTS_VERSION" --dir "$CADIST" --out "$CADIST/INDEX" --ssl1 "$OPENSSL_LOCATION" -format 1 --style new | tail -1)
export NUMBER_OF_CA=$(echo "$TOTAL_CA" | grep -o -E '[0-9]+')

#Verify that $CADIST/INDEX.html[.txt] contains the right number of CAs
CADIST_PEMS=( "$CADIST"/*.pem )
export NUMBER_OF_CA_VERIFY=${#CADIST_PEMS[@]}
if [ "$NUMBER_OF_CA_VERIFY" = "$NUMBER_OF_CA" ];
then
    echo "$CADIST/INDEX.html[.txt] contains the right number of CAs."
else
    echo "$CADIST/INDEX.html[.txt] doesn't contain the right number of CAs."
#[06/25/18]    exit
fi

#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
##Make the MD5 checksums
#cd "$CABASEDIR/$OUR_CERTS_VERSION"
#( cd "$CADIST"; md5sum *.0 *.pem ) > cacerts_md5sum.txt
#cp cacerts_md5sum.txt "$CADIST"

#Make the SHA256 checksums
cd "$CABASEDIR/$OUR_CERTS_VERSION"
( cd "$CADIST"; sha256sum *.0 *.pem ) > cacerts_sha256sum.txt
cp cacerts_sha256sum.txt "$CADIST"

#Update the $CADIST/CHANGES file 
cp "$CABASEDIR/$PREVIOUS_IGTFNEW/certificates/CHANGES" "$CADIST"
echo "edit CHANGES file and remove any temporary editor files like #CHANGES# or CHANGES~"
echo "Hit Enter to continue, else hit CTRL+c."
read USERINPUT
nano "$CADIST/CHANGES"

#Add new distribution to repository and make sure the permissions are OK i.e. rw- r-- r--
cd "$CADIST"
if chmod 644 *
then
    echo "Permissions successfully set."
else
    echo "Failed to set permissions."
    exit 1
fi
cd "$CABASEDIR"
svn add "$OUR_CERTS_VERSION"

#Commit all the changes
svn commit -m "Updated to IGTF version $IGTF_CERTS_VERSION, OSG version $OUR_CERTS_VERSION"



#--------------------Check the CA certificates and CRLs--------------------
#Run fetch-crl
pushd "$CADIST"
#FETCH_CRL_lOCATION=`which fetch-crl`
#$FETCH_CRL_lOCATION -l "$PWD" --out "$PWD"
fetch-crl -l "$PWD" --out "$PWD"

#Check expired or near-expired CRLs
"$CABASEDIR"/check-crl-expiry.pl *.r0

#Check expired or near-expired CAs
"$CABASEDIR"/check-ca-expiry.pl *.pem

#Cleanup
rm -f *.r0
popd



#--------------------Make the CA tarball distribution--------------------
#Make sure the $CABASEDIR directory in your svn workspace is up-to-date and contains no local modifications
cd "$CABASEDIR"
svn status

#Create the tarball
cd "$CABASEDIR/$OUR_CERTS_VERSION"
tar cvfz "osg-certificates-$OUR_CERTS_VERSION.tar.gz" --exclude .svn certificates

#01/27/2020 - removing OSG Security team signatures
#Sign it with the security@opensciencegrid.org PGP key
#while true; do
#    gpg --default-key $OSGSECKEYID -b "osg-certificates-$OUR_CERTS_VERSION.tar.gz"
#    if [ $? -ne 0 ];
#    then
#        echo "Signing failed, retrying."
#    else
#        break
#    fi
#done


#--------------------Make the DEB--------------------

#03/26/2019 - commenting out as DEB release is deprecated

#Make sure CWD is correct
#cd "$CABASEDIR/$OUR_CERTS_VERSION"

#Run the make-deb script
#../make-deb



#--------------------Make manifest and save the distribution files in SVN--------------------
cd "$CABASEDIR/$OUR_CERTS_VERSION"

#Make the manifest
../make-manifest 

#Inspect the manifest file (ca-certs-version)
cat ca-certs-version | grep -q $OUR_CERTS_VERSION
if [ $? -ne 0 ];
then
    echo "Information in ca-certs-version file is incorrect."
    exit
fi

#Set the svn release directory
export SVNDIR=$CABASEDIR/../release

#Copy the files to the svn release directory
cd "$CABASEDIR/$OUR_CERTS_VERSION"
#03/26/19 - DEB release deprecated
#cp "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig" "osg-ca-certs-$OUR_CERTS_VERSION-0.deb" "$SVNDIR"
#01/27/19 - removing Sec team signature
#cp "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig" "$SVNDIR"
cp "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "$SVNDIR"
cp ca-certs-version "$SVNDIR/ca-certs-version-$OUR_CERTS_VERSION"
cp ca-certs-version "$CADIST"
#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
#cp cacerts_md5sum.txt "$SVNDIR/cacerts_md5sum-$OUR_CERTS_VERSION.txt"
cp cacerts_sha256sum.txt "$SVNDIR/cacerts_sha256sum-$OUR_CERTS_VERSION.txt"

#Change to the svn release directory
cd "$SVNDIR"

#Commit the files
#[01/08/19] adding to make MD5 checksum
#03/26/19 - DEB release deprecated
#svn add "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig" "osg-ca-certs-$OUR_CERTS_VERSION-0.deb" "ca-certs-version-$OUR_CERTS_VERSION" "cacerts_md5sum-$OUR_CERTS_VERSION.txt" "cacerts_sha256sum-$OUR_CERTS_VERSION.txt"
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
#svn add "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig" "ca-certs-version-$OUR_CERTS_VERSION" "cacerts_md5sum-$OUR_CERTS_VERSION.txt" "cacerts_sha256sum-$OUR_CERTS_VERSION.txt"
#01/27/19 - removing Sec team signature
#svn add "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig" "ca-certs-version-$OUR_CERTS_VERSION" "cacerts_sha256sum-$OUR_CERTS_VERSION.txt"
svn add "osg-certificates-$OUR_CERTS_VERSION.tar.gz" "ca-certs-version-$OUR_CERTS_VERSION" "cacerts_sha256sum-$OUR_CERTS_VERSION.txt"
svn commit -m "OSG certificates distribution $OUR_CERTS_VERSION"

echo "Process for IGTFNEW is completed."
sleep 5
#--------------------Process for IGTF CA i.e. IGTFNEW is completed.--------------------



#--------------------Process for OSG CA i.e. NEW--------------------
echo "Preparing for OSG CA i.e. NEW..."
#Change to an empty working directory and set $CAWORKDIR to the path
cd `mktemp -d`
export CAWORKDIR=`pwd`

#Checkout or update the OSG svn directories
cd /root/certs/trunk/cadist/CA-Certificates-Base
svn update
export CABASEDIR=`pwd`

#Set the OSG certificates distribution version
echo "Enter our OSG cert version i.e. n.xNEW:"
read OUR_CERTS_VERSION
if [[ $OUR_CERTS_VERSION =~ ^[0-9]+[.][0-9]+(NEW)$ ]];
then
    export OUR_CERTS_VERSION
else
    echo "Please enter a valid our OSG cert version i.e. n.xNEW."
    exit
fi

#Set the variable m.mm
export MMM=$(echo "$OUR_CERTS_VERSION" | grep -o -E '[0-9]+\.[0-9]+')

#Set the previous version of OUR_CERTS_VERSION for OSG
export PREVIOUS_NEW=`echo "$MMM - 0.01" | bc -l`NEW

#Create a new distribution directory for the release
cd $CABASEDIR
mkdir -p $OUR_CERTS_VERSION/certificates
export CADIST=$CABASEDIR/$OUR_CERTS_VERSION/certificates

#Download the new IGTF distribution tarball (and PGP signature) from http://dist.eugridpma.info/distribution/igtf/current 
cd $CAWORKDIR
wget http://dist.eugridpma.info/distribution/igtf/current/igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz
wget http://dist.eugridpma.info/distribution/igtf/current/igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz.asc

#Verify the PGP signature on the tarball
gpg --verify igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz.asc
if [ $? -ne 0 ];
then
    echo "PGP signature verification failed."
    exit
else
    echo "Signature is good."
fi

#Unpack the certificates
tar xzf igtf-policy-installation-bundle-$IGTF_CERTS_VERSION.tar.gz

#Select the CAs and install to temporary location
cd igtf-policy-installation-bundle-$IGTF_CERTS_VERSION
./configure --prefix=$CADIST --with-profile=classic --with-profile=mics --with-profile=slcs --with-profile=iota
make install

#Install the non-IGTF CAs
#echo "Install the non-IGTF CAs. Once done, Hit Enter to continue, else hit CTRL+c."
#read VARIABLES
sh /root/le.sh
if [ $? -ne 0 ];
then
    echo "non-IGTF CA installation failed"
    exit
else
    echo "non-IGTF CA installation completed."
fi

#Compare differences with previous version
#Make sure appropriate extra CA files from $CABASEDIR/non-igtf-certificates are included or removed from the distribution directory $CADIST
cd $CADIST
for ca in * ; do echo $ca; diff $ca $CABASEDIR/$PREVIOUS_NEW/certificates; done
for ca in $CABASEDIR/$PREVIOUS_NEW/certificates/* ; do echo $ca; diff $ca . ; done

#Generate the index files
cd $CABASEDIR
OPENSSL_LOCATION=`which openssl`
./mk-index.pl --version $OUR_CERTS_VERSION --dir $CADIST --out $CADIST/INDEX --ssl1 $OPENSSL_LOCATION -format 1 --style new
TOTAL_CA=$(./mk-index.pl --version $OUR_CERTS_VERSION --dir $CADIST --out $CADIST/INDEX --ssl1 $OPENSSL_LOCATION -format 1 --style new | tail -1)
export NUMBER_OF_CA=$(echo $TOTAL_CA | grep -o -E '[0-9]+')

#Verify that $CADIST/INDEX.html[.txt] contains the right number of CAs
export NUMBER_OF_CA_VERIFY=$(ls $CADIST/*.pem | wc -l)
if [ "$NUMBER_OF_CA_VERIFY" = "$NUMBER_OF_CA" ];
then
    echo "$CADIST/INDEX.html[.txt] contains the right number of CAs."
else
    echo "$CADIST/INDEX.html[.txt] doesn't contain the right number of CAs."
#[06/25/18]    exit
fi

#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
##Make the MD5 checksums
#cd $CABASEDIR/$OUR_CERTS_VERSION
#( cd $CADIST; md5sum *.0 *.pem ) > cacerts_md5sum.txt
#cp cacerts_md5sum.txt $CADIST

#Make the SHA256 checksums
cd $CABASEDIR/$OUR_CERTS_VERSION
( cd $CADIST; sha256sum *.0 *.pem ) > cacerts_sha256sum.txt
cp cacerts_sha256sum.txt $CADIST

#Update the $CADIST/CHANGES file
cp $CABASEDIR/$PREVIOUS_NEW/certificates/CHANGES $CADIST
echo "edit CHANGES file and remove any temporary editor files like #CHANGES# or CHANGES~"
echo "Hit Enter to continue, else hit CTRL+c."
read USERINPUT
nano $CADIST/CHANGES

#Add new distribution to repository and make sure the permissions are OK i.e. rw- r-- r--
cd $CADIST; chmod 644 *
export PERMISSIONS=$(ls -l *crl_url *info *pem | shuf -n 1)
if [[ "$PERMISSIONS" =~ "-rw-r--r--" ]];
then
    echo "Permissions are correct."
else
    echo "Permissions are incorrect."
    exit
fi
cd $CABASEDIR
svn add $OUR_CERTS_VERSION

#Commit all the changes
svn commit -m "Updated to IGTF version $IGTF_CERTS_VERSION, OSG version $OUR_CERTS_VERSION"



#--------------------Check the CA certificates and CRLs--------------------
#Run fetch-crl
pushd $CADIST
FETCH_CRL_lOCATION=`which fetch-crl`
$FETCH_CRL_lOCATION -l `pwd` --out `pwd`

#Check expired or near-expired CRLs
$CABASEDIR/check-crl-expiry.pl *.r0

#Check expired or near-expired CAs
$CABASEDIR/check-ca-expiry.pl *.pem

#Cleanup
rm -f *.r0
popd



#--------------------Make the CA tarball distribution--------------------
#Make sure the $CABASEDIR directory in your svn workspace is up-to-date and contains no local modifications
cd $CABASEDIR
svn status

#Create the tarball
cd $CABASEDIR/$OUR_CERTS_VERSION
tar cvfz osg-certificates-$OUR_CERTS_VERSION.tar.gz --exclude .svn certificates

#01/27/2020 - removing OSG Security team signatures
#Sign it with the security@opensciencegrid.org PGP key
#export OSGSECKEYID=7FD42669
#while true; do
#    gpg --default-key $OSGSECKEYID -b osg-certificates-$OUR_CERTS_VERSION.tar.gz
#    if [ $? -ne 0 ];
#    then
#        echo "Signing failed, retrying."
#    else
#        break
#    fi
#done


#--------------------Make the DEB--------------------

#03/26/2019 - commenting out as DEB release is deprecated

#Make sure CWD is correct
#cd $CABASEDIR/$OUR_CERTS_VERSION

#Run the make-deb script
#../make-deb



#--------------------Make manifest and save the distribution files in SVN--------------------
cd $CABASEDIR/$OUR_CERTS_VERSION

#Make the manifest
../make-manifest

#Inspect the manifest file (ca-certs-version)
cat ca-certs-version | grep -q $OUR_CERTS_VERSION
if [ $? -ne 0 ];
then
    echo "Information in ca-certs-version file is incorrect."
    exit
fi

#Set the svn release directory
export SVNDIR=$CABASEDIR/../release

#Copy the files to the svn release directory
cd $CABASEDIR/$OUR_CERTS_VERSION
#03/26/19 - DEB release deprecated
#cp osg-certificates-$OUR_CERTS_VERSION.tar.gz osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig osg-ca-certs-$OUR_CERTS_VERSION-0.deb $SVNDIR
#01/27/20 - remove Secteam signature
#cp osg-certificates-$OUR_CERTS_VERSION.tar.gz osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig $SVNDIR
cp osg-certificates-$OUR_CERTS_VERSION.tar.gz $SVNDIR
cp ca-certs-version $SVNDIR/ca-certs-version-$OUR_CERTS_VERSION
cp ca-certs-version $CADIST
#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
#cp cacerts_md5sum.txt $SVNDIR/cacerts_md5sum-$OUR_CERTS_VERSION.txt
cp cacerts_sha256sum.txt $SVNDIR/cacerts_sha256sum-$OUR_CERTS_VERSION.txt

#Change to the svn release directory
cd $SVNDIR

#Commit the files
#[01/08/19] adding to make MD5 checksum
#03/26/19 - DEB release deprecated
#svn add osg-certificates-$OUR_CERTS_VERSION.tar.gz osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig osg-ca-certs-$OUR_CERTS_VERSION-0.deb ca-certs-version-$OUR_CERTS_VERSION cacerts_md5sum-$OUR_CERTS_VERSION.txt cacerts_sha256sum-$OUR_CERTS_VERSION.txt;
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
#svn add osg-certificates-$OUR_CERTS_VERSION.tar.gz osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig ca-certs-version-$OUR_CERTS_VERSION cacerts_md5sum-$OUR_CERTS_VERSION.txt cacerts_sha256sum-$OUR_CERTS_VERSION.txt;
#01/27/20 - remove Secteam signature
#svn add osg-certificates-$OUR_CERTS_VERSION.tar.gz osg-certificates-$OUR_CERTS_VERSION.tar.gz.sig ca-certs-version-$OUR_CERTS_VERSION cacerts_sha256sum-$OUR_CERTS_VERSION.txt; 
svn add osg-certificates-$OUR_CERTS_VERSION.tar.gz ca-certs-version-$OUR_CERTS_VERSION cacerts_sha256sum-$OUR_CERTS_VERSION.txt; 
svn commit -m "OSG certificates distribution $OUR_CERTS_VERSION"

echo "Process for OSG CA i.e. NEW is completed."
sleep 5
#--------------------Process for NEW is completed.--------------------
#--------------------Processes for multiple caches are completed--------------------



#--------------------Create a release using Koji--------------------
echo "Creating a release using Koji..."

#--------------------Setup/Preparation--------------------
#Ensure that /etc/yum.conf has the following line in the [main] section, thereby enabling Yum plugins, including the priorities one: plugins=1
if grep -q plugins=1 /etc/yum.conf; then
    echo "yum.conf file is good."
else
    echo "Set plugins=1 in yum.conf file."
    exit
fi

#Install OSG repositories (command only for RHEL 7, CentOS 7, and SL 7)
#rpm -Uvh https://repo.opensciencegrid.org/osg/3.4/osg-3.4-el7-release-latest.rpm

#Check out the package source from subversion
#svn co https://vdt.cs.wisc.edu/svn/native/redhat 


#--------------------Building RPM packages--------------------
##[05/28/19]Copy the tar balls to VDT upstream machine (library.cs.wisc.edu)
#[05/28/19]ssh "${USERNAME_VDT}@library.cs.wisc.edu" "mkdir /p/vdt/public/html/upstream/osg-ca-certs/$MMM/ /p/vdt/public/html/upstream/igtf-ca-certs/$NNN"

#Copy the tar balls to VDT upstream machine (moria.cs.wisc.edu)
ssh "${USERNAME_VDT}@moria.cs.wisc.edu" "mkdir /p/vdt/public/html/upstream/osg-ca-certs/$MMM/ /p/vdt/public/html/upstream/igtf-ca-certs/$NNN"

#Run following command in the same terminal where you did all the previous steps
cd "$SVNDIR"
#[05/28/19]scp osg-certificates-${MMM}NEW.tar.gz "${USERNAME_VDT}@library.cs.wisc.edu:/p/vdt/public/html/upstream/osg-ca-certs/$MMM/"
#[05/28/19]scp osg-certificates-${LLL}IGTF*.tar.gz "${USERNAME_VDT}@library.cs.wisc.edu:/p/vdt/public/html/upstream/igtf-ca-certs/$NNN/"
scp osg-certificates-${MMM}NEW.tar.gz "${USERNAME_VDT}@moria.cs.wisc.edu:/p/vdt/public/html/upstream/osg-ca-certs/$MMM/"
scp osg-certificates-${LLL}IGTF*.tar.gz "${USERNAME_VDT}@moria.cs.wisc.edu:/p/vdt/public/html/upstream/igtf-ca-certs/$NNN/"

#Do svn update  
cd /root/redhat/trunk/; 
svn update;

#Edit the spec and upstream files for both the rpm packages we produce to point to new release. 
#The rpms to be updated include osg-ca-certs & igtf-ca-certs. 
#For spec file you need to update Version:, Release:, Source0: and add comment in change log. 
#For upstream file you need to update the tarball location.

#----------For osg-ca-certs----------
cd osg-ca-certs;   
echo "Edit Version to m.mm; release to 1; edit Source0 to osg-certificates-m.mmNEW.tar.gz; and add appropriate entry to changelog"
echo "Hit Enter to continue, else hit CTRL+c."
read VARIABLES
nano osg/osg-ca-certs.spec
echo "Update location to osg-ca-certs/m.mm/osg-certificates-m.mmNEW.tar.gz"
echo "Hit Enter to continue, else hit CTRL+c."
read VARIABLES
nano upstream/osg-certificates-NEW.source;

#Create a test build on local environment and Koji
osg-build rpmbuild .; 
#[11/08/18] commenting out the following code to remove OSG 3.3
#Step for branch 3.3: 
#osg-build --repo=3.3 rpmbuild .;
#[10/21/19] adding following lines of code to include OSG branch 3.4
#Step for branch 3.4
osg-build --repo=3.4 rpmbuild .;


#Create a hidden directory with name ‘globus’
mkdir /root/.globus

echo "Have you already converted your user certificate (.p12) file into userkey.pem file (without the certificate) and into usercert.pem file (without the key)?"
read -p "Enter yes or no..." CONVERTED
if [ "$CONVERTED" = "no" ];
then
    echo "Export the OSG user certificate (.p12) from your local system and import it in this system and store in '/root/.globus' directory."
    echo "Hit Enter once it is done, else hit CTRL+c."
    read VARIABLES
    echo "What is the name of a OSG user certificate (.p12) file?"
    read USER_CERTIFICATE_AND_KEY
    #Convert user certificate (.p12) file into userkey.pem file without the certificate
    openssl pkcs12 -in "/root/.globus/$USER_CERTIFICATE_AND_KEY" -out /root/.globus/userkey.pem -nodes -nocerts
    chmod 600 /root/.globus/userkey.pem
    #Convert user certificate (.p12) file into usercert.pem file without the key
    openssl pkcs12 -in "/root/.globus/$USER_CERTIFICATE_AND_KEY" -out /root/.globus/usercert.pem -nodes -nokeys
fi

grid-proxy-init 
osg-build --scratch koji .
#[11/08/18] commenting out the following code to remove OSG 3.3
#Step for branch 3.3: 
#osg-build --repo=3.3 --scratch koji .
#[10/21/19] adding following lines of code to include OSG branch 3.4
#Step for branch 3.4
osg-build --repo=3.4 --scratch koji .
#--------------------

#----------For igtf-ca-certs----------
cd ../igtf-ca-certs
echo "Edit Version to n.nn; edit release to 1; edit Source0 to osg-certificates-m.mmIGTFNEW.tar.gz; and add appropriate entry to changelog"
echo "Hit Enter to continue, else hit CTRL+c."
read VARIABLES
nano osg/igtf-ca-certs.spec 
echo "Update location to igtf-ca-certs/n.nn/osg-certificates-m.mmIGTFNEW.tar.gz;"
echo "Hit Enter to continue, else hit CTRL+c."
read VARIABLES
nano upstream/osg-certificates-IGTFNEW.source; 

#Create a test build on local environment and Koji
osg-build rpmbuild .;
#[11/08/18] commenting out the following code to remove OSG 3.3
#Step for branch 3.3:
#osg-build --repo=3.3 rpmbuild .;
#[10/21/19] adding following lines of code to include OSG branch 3.4
#Step for branch 3.4
osg-build --repo=3.4 rpmbuild .;

osg-build --scratch koji .
#[11/08/18] commenting out the following code to remove OSG 3.3
#Step for branch 3.3:
#osg-build --repo=3.3 --scratch koji .
#[10/21/19] adding following lines of code to include OSG branch 3.4
#Step for branch 3.4
osg-build --repo=3.4 --scratch koji .
#--------------------

#Check in the changes to SVN 
cd /root/redhat/trunk/; 
svn commit -m "Test builds-OSG certificates distribution $OUR_CERTS_VERSION. (Jira Ticket: $JIRA_TICKET)"

#Create official builds on Koji for EL6 and EL7
cd /root/redhat/trunk/
osg-build koji --el6 osg-ca-certs
osg-build koji --el7 osg-ca-certs
osg-build koji --el6 igtf-ca-certs
osg-build koji --el7 igtf-ca-certs

#[11/08/18] commenting out the following code to remove OSG 3.3
#----------Steps for branch-osg 3.3--------------
#echo "Performing the steps for OSG repo 3.3"

#cd /root/redhat/branches
#svn up .
#cd /root/redhat
#svn up trunk/osg-ca-certs
#svn up trunk/igtf-ca-certs

#Find your latest commit revision number:
#svn log -l 5 trunk/osg-ca-certs

#Find the latest revision number and get all the differences between it and the previous one in the SVN.
#Purpose: to find the difference in `trunk/osg-ca-certs` before and after your change
#and merge that change into `branches/osg-3.3/osg-ca-certs` For example, revision 23621
#was a copy of osg-ca-certs before your update and 23622 was your update. So, the
#difference between 23622 and 23621 encompasses all the changes you made

#echo "Enter the latest version number (e.g. 23622) since the previous commit"
#read LATESTCOMMIT

#cd /root/redhat/branches/osg-3.3/osg-ca-certs
#svn merge -c "${LATESTCOMMIT}" ../../../trunk/osg-ca-certs .
#cd /root/redhat/branches/osg-3.3/igtf-ca-certs
#svn merge -c "${LATESTCOMMIT}" ../../../trunk/igtf-ca-certs .

#cd /root/redhat/branches/osg-3.3
#svn commit -m "Official builds-OSG certificates distribution $OUR_CERTS_VERSION. (Jira Ticket: $JIRA_TICKET)"
#osg-build koji --el6 --repo=3.3 osg-ca-certs
#osg-build koji --el7 --repo=3.3 osg-ca-certs
#osg-build koji --el6 --repo=3.3 igtf-ca-certs
#osg-build koji --el7 --repo=3.3 igtf-ca-certs

#----------Steps for branch-osg 3.3 are done--------------



#[10/21/19] adding following lines of code to include OSG branch 3.4
#----------Steps for branch-osg 3.4--------------
echo "Performing the steps for OSG repo 3.4"

cd /root/redhat/branches
svn up .
cd /root/redhat
svn up trunk/osg-ca-certs
svn up trunk/igtf-ca-certs

#Find your latest commit revision number:
svn log -l 5 trunk/osg-ca-certs

#Find the latest revision number and get all the differences between it and the previous one in the SVN.
#Purpose: to find the difference in `trunk/osg-ca-certs` before and after your change
#and merge that change into `branches/osg-3.4/osg-ca-certs` For example, revision 23621
#was a copy of osg-ca-certs before your update and 23622 was your update. So, the
#difference between 23622 and 23621 encompasses all the changes you made

echo "Enter the latest version number (e.g. 23622) since the previous commit"
read LATESTCOMMIT

cd /root/redhat/branches/osg-3.4/osg-ca-certs
svn merge -c "${LATESTCOMMIT}" ../../../trunk/osg-ca-certs .
cd /root/redhat/branches/osg-3.4/igtf-ca-certs
svn merge -c "${LATESTCOMMIT}" ../../../trunk/igtf-ca-certs .

cd /root/redhat/branches/osg-3.4
svn commit -m "Official builds-OSG certificates distribution $OUR_CERTS_VERSION. (Jira Ticket: $JIRA_TICKET)"
osg-build koji --el6 --repo=3.4 osg-ca-certs
osg-build koji --el7 --repo=3.4 osg-ca-certs
osg-build koji --el6 --repo=3.4 igtf-ca-certs
osg-build koji --el7 --repo=3.4 igtf-ca-certs

#----------Steps for branch-osg 3.4 are done--------------



#Check in the changes to SVN
cd /root/redhat/trunk/; 
svn commit -m "OSG certificates distribution $OUR_CERTS_VERSION. (Jira Ticket: $JIRA_TICKET)"
echo "Update the Jira ticket by mentioning that you have created the builds."


#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
##Verify MD5 and SHA256 hash of new OSG tarballs
#Verify SHA256 hash of new OSG tarballs
cd /root/certs/trunk/cadist/CA-Certificates-Base/${MMM}NEW/

#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
#MD5SUM_NEW=`md5sum osg-certificates-${MMM}NEW.tar.gz | awk '{print $1}'`
#if cat ca-certs-version | grep -q $MD5SUM_NEW;
#then
#    echo "MD5 hash for osg-certificates-${MMM}NEW.tar.gz is correct."
#else
#    echo "MD5 hash for osg-certificates-${MMM}NEW.tar.gz is incorrect."
#    exit
#fi

SHA256SUM_NEW=`sha256sum osg-certificates-${MMM}NEW.tar.gz | awk '{print $1}'`
if cat ca-certs-version | grep -q $SHA256SUM_NEW;
then
    echo "SHA256 hash for osg-certificates-${MMM}NEW.tar.gz is correct."
else
    echo "SHA256 hash for osg-certificates-${MMM}NEW.tar.gz is incorrect."
    exit
fi

#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
##Verify MD5 and SHA256 hash of new IGTF tarballs
#Verify SHA256 hash of new IGTF tarballs
cd /root/certs/trunk/cadist/CA-Certificates-Base/${LLL}IGTFNEW

#[01/08/19] adding to make MD5 checksum
#[10/21/19] dropping MD5 checksum [SOFTWARE-3005]
#MD5SUM_IGTFNEW=`md5sum osg-certificates-${LLL}IGTFNEW.tar.gz | awk '{print $1}'`
#if cat ca-certs-version | grep -q $MD5SUM_IGTFNEW;
#then
#    echo "MD5 hash for osg-certificates-${LLL}IGTFNEW.tar.gz is correct."
#else
#    echo "MD5 hash for osg-certificates-${LLL}IGTFNEW.tar.gz is incorrect."
#     exit
#fi

SHA256SUM_IGTFNEW=`sha256sum osg-certificates-${LLL}IGTFNEW.tar.gz | awk '{print $1}'`
if cat ca-certs-version | grep -q $SHA256SUM_IGTFNEW;
then
    echo "SHA256 hash for osg-certificates-${LLL}IGTFNEW.tar.gz is correct."
else
    echo "SHA256 hash for osg-certificates-${LLL}IGTFNEW.tar.gz is incorrect."
    exit
fi


#Test the new builds
echo "Perform extensive testing." 
#[11/08/18] commenting out the following code to remove OSG 3.3
#echo "On the fresh SL6 & SL7 VMs, run test-script-SL6-OSG3.3, test-script-SL6-OSG3.4, test-script-SL7-OSG3.3 and test-script-SL7-OSG3.4 respectively."
#[10/21/19] adding following lines of code to include OSG branch 3.4
#echo "On the fresh SL6 & SL7 VMs, run test-script-SL6-OSG3.4 and test-script-SL7-OSG3.4 respectively."
echo "On the fresh SL6 & SL7 VMs, run test-script-SL6-OSG3.4, test-script-SL6-OSG3.5, test-script-SL7-OSG3.4 and test-script-SL7-OSG3.5 respectively."
echo "Update the Jira ticket by mentioning that you are done with the testing."
echo "Hit Enter once the testing is done."
read VARIABLES



#Promote the Koji builds to osg-testing repository
#Release EL6 and EL7 builds for testing
cd /root/redhat/trunk/;
grid-proxy-init
osg-promote osg-ca-certs igtf-ca-certs
#[11/08/18] commenting out the following code to remove OSG 3.3
#osg-promote -r 3.3-testing osg-ca-certs igtf-ca-certs
#[10/21/19] adding following lines of code to include OSG branch 3.4
osg-promote -r 3.4-testing osg-ca-certs igtf-ca-certs
echo "Update the Jira ticket and change the workflow from open/in progress -> Ready for Testing"

