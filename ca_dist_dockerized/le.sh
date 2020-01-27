#!/bin/sh

git clone https://github.com/cilogon/letsencrypt-certificates.git
cd letsencrypt-certificates
make check
make install
find -type f -name '*.txt' | while read f; do mv "$f" "${f%.txt}"; done
cp isrgrootx1.* $CABASEDIR/non-igtf-certificates
cp letsencryptauthorityx* $CABASEDIR/non-igtf-certificates
cd $CABASEDIR/non-igtf-certificates
cp isrgrootx1.* $CADIST
cp letsencryptauthorityx* $CADIST
cd $CADIST
ln -s isrgrootx1.pem 4042bcee.0
ln -s isrgrootx1.signing_policy 4042bcee.signing_policy
ln -s isrgrootx1.pem 6187b673.0
ln -s isrgrootx1.signing_policy 6187b673.signing_policy
ln -s letsencryptauthorityx3.pem 4a0a35c0.0
ln -s letsencryptauthorityx3.signing_policy 4a0a35c0.signing_policy
ln -s letsencryptauthorityx3.pem 4f06f81d.0
ln -s letsencryptauthorityx3.signing_policy 4f06f81d.signing_policy
ln -s letsencryptauthorityx4.pem 23c2f850.0
ln -s letsencryptauthorityx4.signing_policy 23c2f850.signing_policy
ln -s letsencryptauthorityx4.pem 929e297e.0
ln -s letsencryptauthorityx4.signing_policy 929e297e.signing_policy 