FROM centos:7
ENV container docker
WORKDIR /root
USER root

#dependencies
#---------------------------------------------------------------
RUN yum update -y 
RUN yum -y install epel-release
#[10/21/19] updating the following line for OSG 3.5
#RUN rpm -Uvh https://repo.opensciencegrid.org/osg/3.4/osg-3.4-el7-release-latest.rpm
RUN rpm -Uvh https://repo.opensciencegrid.org/osg/3.5/osg-3.5-el7-release-latest.rpm
RUN rpm -Uvh https://downloads.globus.org/toolkit/gt6/stable/installers/repo/rpm/globus-toolkit-repo-latest.noarch.rpm 
RUN yum repolist
RUN yum -y groups install "Development Tools"
RUN yum -y install \
		   svn \
		   rpm-build ncurses-devel \
		   perl-LWP-Protocol-https \
		   perl-Sys-Syslog \
		   yum-plugin-priorities \
		   fetch-crl \
		   bc \
		   wget \
		   fakeroot \
		   nano \
		   cpan \
		   perl \
		   perl-core \
		   globus-data-management-client \
		   which

#[10/21/19] the Software team has moved osg-build to the devops repo
RUN yum -y install --enablerepo=devops-itb osg-build

#set up perl
RUN mkdir -p /perl ; mkdir -p /perl/lib/perl5 ;
ENV PERL_PATH=/perl
ENV PERL5LIB=$PERL_PATH:$PERL_PATH/lib/perl5:$PERL5LIB
ENV PERL_MM_OPT="INSTALL_BASE=$PERL_PATH"
ENV PERL_MB_OPT="--install_base $PERL_PATH"
ENV PATH="$PERL_PATH/bin$PATH"
RUN cpan install Date::Parse

#01/27/2020 - removing OSG Security team signatures
#set other env variables
#ENV OSGSECKEYID=7FD42669

#build the debian build tools, add to PATH
RUN svn co https://vdt.cs.wisc.edu/svn/certs/trunk/vdt-scripts/
COPY build-debian-tools /root/vdt-scripts/
RUN sh /root/vdt-scripts/build-debian-tools
RUN echo "source /root/debian-build-tools/setup.sh" >> /root/.bashrc

#get and install IGTF GPG key
RUN wget https://dist.igtf.net/distribution/current/GPG-KEY-EUGridPMA-RPM-3
RUN gpg --import GPG-KEY-EUGridPMA-RPM-3

#get OSG certs
RUN svn co https://vdt.cs.wisc.edu/svn/certs

#install latest OSG software

RUN svn co https://vdt.cs.wisc.edu/svn/native/redhat 

#copy files
#---------------------------------------------------------------
COPY ca_dist.sh /root
RUN chmod +x /root/ca_dist.sh
RUN mkdir /root/.globus
COPY userkey.pem /root/.globus
COPY usercert.pem /root/.globus
RUN chmod 600 /root/.globus/*
#01/27/2020 - removing OSG Security team signatures
#COPY 7FD42669.asc /root
COPY le.sh /root
RUN chmod +x /root/le.sh
