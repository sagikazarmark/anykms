AWS Signature Version 4 test vectors, copied unchanged from
https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4
(Apache License 2.0, Copyright Amazon.com, Inc. or its affiliates).

Only the header-signing files of cases that do not exercise path normalization are vendored
(KMS always posts to `/`). Used by `src/sigv4.rs` (`aws_test_suite_vectors`).
