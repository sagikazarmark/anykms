# AWS Emulator (https://github.com/aws/aws-emulator), for the AWS conformance suite. AWS publishes
# no image: this follows its Docker guide, with the base image and the package pinned. AWS signs
# the packages (`<package>.sig`, key 98BC F336 A3BE 53B7 34E9 67C5 2E5B F49B D940 F624); each
# checksum below is of a package whose signature was verified.
#
# To update: pick a version from
# https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/versions.json (1.0.337.1 is
# package 1.0.337-1), verify both packages' signatures and replace the version and checksums.
ARG BASE=public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:158a9044f9dc0777f098b76c8b54346f6ed4560b9a6a416dec7a5ba3bc483af4

FROM ${BASE} AS base

FROM base AS package-amd64
ADD --checksum=sha256:6dad27f30a9e17d58f6e8ffb8bfab41b80767b4700ac455044c65ff1cab3c0fd \
    https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/aws-emulator-1.0.337-1-x86_64.rpm \
    /aws-emulator.rpm

FROM base AS package-arm64
ADD --checksum=sha256:2ca59080b63c9101997ca7387c6ce86aa546903b5dcb03607a7e92693172469d \
    https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/aws-emulator-1.0.337-1-aarch64.rpm \
    /aws-emulator.rpm

FROM package-${TARGETARCH} AS package

FROM base
# Any user may run it (compose passes the host's, so the files it writes are readable there).
RUN --mount=type=bind,from=package,source=/aws-emulator.rpm,target=/tmp/aws-emulator.rpm \
    rpm -i /tmp/aws-emulator.rpm \
    && mkdir -p /home/emulator/.aws/emulator \
    && chmod -R 1777 /home/emulator
USER 1000
ENV HOME=/home/emulator EMULATOR_TELEMETRY=off
EXPOSE 9297
ENTRYPOINT ["aws-emulator", "-b", "0.0.0.0", "--telemetry", "off"]
