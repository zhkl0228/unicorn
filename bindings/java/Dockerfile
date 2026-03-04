FROM centos:7

RUN sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|^#[ ]*baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    yum install -y epel-release && \
    yum install -y gcc cmake3 make git java-1.8.0-openjdk-devel && \
    yum clean all

ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk

ARG UNICORN_COMMIT=unknown
RUN git clone --depth 1 -b master https://github.com/zhkl0228/unicorn /build/unicorn

WORKDIR /build/unicorn
RUN mkdir build && cd build && \
    cmake3 .. -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DUNICORN_BUILD_SHARED=OFF \
              -DUNICORN_ARCH="arm aarch64" && \
    make -j$(nproc)

WORKDIR /build/jni
COPY unicorn_Unicorn.c unicorn_Unicorn.h khash.h CMakeLists.txt ./

RUN mkdir build && cd build && \
    cmake3 .. -DUNICORN_HOME=/build/unicorn \
              -DUNICORN_BUILD=/build/unicorn/build && \
    make VERBOSE=1

CMD ["cp", "/build/jni/build/libunicorn_java.so", "/output/libunicorn_java.so"]
