FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>

ADD filter-cmd-linux-amd64 filter-cmd
VOLUME /etc/chremoas

ENTRYPOINT ["/filter-cmd", "--configuration_file", "/etc/chremoas/chremoas.yaml"]
