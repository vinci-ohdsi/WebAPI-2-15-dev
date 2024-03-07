```Mermaid
flowchart TD;
    A[Atlas View shared] --> B{No change};
    B --> |yes| C(Use existing data for GWAS);
    B --> |no| D(Copy and edit);
    D --> E(Generate);
    E --> F(Use new in GWAS);
    F -.-> G{Change is sharable};
    G -.-> H(Copied to an shared author account);
```
