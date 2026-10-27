# Pharos Proposals

Draft proposals for the Pharos ecosystem, including EIP-style specifications and
protocol designs. This repository provides a shared place to describe proposed
changes, explain their rationale, and refine them through technical review.

Documents in this repository are proposals. Their inclusion or merge does not
establish protocol adoption, implementation, or acceptance into the Ethereum EIP
process.

## Proposal index

| Proposal | Status | Summary |
| --- | --- | --- |
| [Sponsored Transactions](proposals/sponsored_transaction.md) | Draft | A sponsored transaction format that separates gas payment from sender identity and value transfer, with payer authorization and vault-based fee settlement. |

## Repository structure

```text
.
├── README.md                         # Overview and proposal index
├── proposals/
│   └── sponsored_transaction.md       # Sponsored Transactions
└── templates/
    └── proposal_template.md           # Starting point for new proposals
```

Proposals live together in `proposals/` so that their paths remain stable as they
evolve. Use descriptive filenames in `snake_case`. Add supporting diagrams or
other assets alongside a proposal in a dedicated subdirectory when needed.

## Reading and review

Read each proposal's abstract and motivation for context, then use its contents
list to navigate the specification and supporting discussion. Reviewers should
check that requirements are precise, examples agree with the specification, and
compatibility and security tradeoffs are explicit.

Proposal-specific questions and unresolved choices belong in the document or its
pull request so that the reasoning remains available to future readers.
