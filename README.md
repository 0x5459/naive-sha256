
## A naive sha256 implementation.

### Examples
```rust
use naive_sha256::Sha256;

// create a Sha256 object
let mut hasher = Sha256::new();
// write input message "hello world"
hasher.update(b"hello ");
hasher.update(b"world");
let result = hasher.finalize();

assert_eq!(
    hex::encode(result),
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
);
```
[sha256sum](examples/sha256sum.rs) - Compute SHA256 (256-bit) checksums.

## Reference
- [Sha256 WIKI](https://en.wikipedia.org/wiki/SHA-2)
- [Sha256 Algorithm Explained](https://sha256algorithm.com)