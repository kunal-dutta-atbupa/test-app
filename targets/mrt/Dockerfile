# Mirrors targets/canary/Dockerfile from the reference harness.
# Debian-based gcc:14 (no default _FORTIFY_SOURCE), ASAN build.
FROM gcc:14

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 xxd file gdb && \
    rm -rf /var/lib/apt/lists/*

COPY src/mrt.c /work/mrt.c
COPY fixtures /work/fixtures

# -O1: ASAN-recommended. -fno-omit-frame-pointer: readable stacks.
RUN gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -o /work/mrt /work/mrt.c

CMD ["/bin/bash"]
