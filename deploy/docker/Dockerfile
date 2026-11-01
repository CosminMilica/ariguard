FROM ubuntu:24.04
COPY bin/ariguard-agent /usr/local/bin/ariguard-agent
COPY bin/ariguard.bpf.o /opt/ariguard/ariguard.bpf.o
COPY testdata/golden/policy-full.bin /opt/ariguard/policy.bin
ENTRYPOINT ["/usr/local/bin/ariguard-agent"]
CMD ["--object=/opt/ariguard/ariguard.bpf.o", "--bundle=/opt/ariguard/policy.bin"]
