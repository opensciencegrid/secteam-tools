#OSG CA Distribution Docker

* make sure to replace 'userkey.pem' and 'usercert.pem' with your grid certificate
* currently this container must be run in interactive mode
** example: docker run -it ca_dist bash

#TODO
* remove Debian build tools
* move interactive input to environmental variables
* automate release note creation
* optimize Dockerfile
