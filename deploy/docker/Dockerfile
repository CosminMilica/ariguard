FROM ubuntu:24.04
COPY bin/statewall-agent /usr/local/bin/statewall-agent
COPY bin/statewall.bpf.o /opt/statewall/statewall.bpf.o
COPY testdata/golden/policy.bin /opt/statewall/policy.bin
ENTRYPOINT ["/usr/local/bin/statewall-agent"]
CMD ["--object=/opt/statewall/statewall.bpf.o", "--bundle=/opt/statewall/policy.bin"]
