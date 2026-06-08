Remove indirections in procedures using pooling to enable the usage of buffers
in the stack, which improves cache line utilization, making the execution faster.
Removing the sync.Pool usage also will reduce the total amount of instructions, 
and branching, contributing to faster code.

Implement the bindings to libsecp256k1.

