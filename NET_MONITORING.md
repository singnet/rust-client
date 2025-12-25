0. Follow nodes' logs. Check that blocks are being processed and that no node is stuck on a particular block. Keep track of the latest block number.

1. Epoch-info via observer node
```bash
cargo run -- epoch-info -H <HOST> --grpc-port <GRPC_PORT> --http-port <HTTP_PORT>
```
Check `Current Block` and other fields for sanity.

2. Last finalized block
Run commands via both observer node and some other node (or even all nodes, if something is wrong). 
Compare outputs of both commands. They shouldn't be different (however, a small discrepancy is acceptable). The last finalized block shouldn't be far behind or far ahead of what was seen in logs from step `0`.
```bash
cargo run -- last-finalized-block -H <OBSERVER_HOST> --http-port <OBSERVER_HTTP_PORT>
cargo run -- last-finalized-block -H <NODE_HOST> --http-port <NODE_HTTP_PORT>
```

3. Check a non-empty wallet balance via observer node.
Verify that the `wallet-balance` command is working. Then compare the actual balance with the expected balance.
```bash
cargo run -- wallet-balance --address <ADDRESS_1> 
```

Keep in mind the `Block number` field from the command's output — it's actually the last finalized block. Compare it with the result from step `2`.

4. Transfer funds 
Run this command to transfer funds from your wallet (which must be created and funded from faucet) to <ADDRESS_1> from the previous step. <NODE_HOST> is the node that will produce the block containing this transfer.

**NOTE:** It's better to specify all args explicitly to avoid missing something.
```bash
cargo run -- transfer --to-address <ADDRESS_1> --amount 700 --private-key <YOUR_PRIVATE_KEY> --observer-host <OBSERVER_HOST> --observer-grpc-port <OBSERVER_GRPC_PORT> -H <NODE_HOST> --grpc-port <NODE_GRPC_PORT> --http-port <NODE_HTTP_PORT>
```

Check that the transfer is successful. If waiting fails, you can specify `--max-wait` and `--check-interval` explicitly (check `./src/args.rs` to see what args may be used for other commands as well).

5. Check changes in wallet balances from the transfer
```bash
cargo run -- wallet-balance --address <ADDRESS_1> 
cargo run -- wallet-balance --address <YOUR_ADDRESS> 
```

<ADDRESS_1> must have increased by the sent amount. <YOUR_ADDRESS> must have decreased by the sent amount plus fees.

Check the `Block number` field from the command's output and run `last-finalized-block` again to verify that the blocks are the same (or there's only a very small difference).

6. Check database corruption
Verify that there is a sequence of blocks, one after another, in ascending order. If you request 10 blocks that actually exist, the command must output 10 records (or possibly more under some circumstances) with block info, and fault tolerance must be equal to 1.

Corruption can be checked using different block ranges by specifying start block as `-s` and end block as `-e`. For example:
```bash
cargo run -- get-blocks-by-height -s 1 -e 22 -H <OBSERVER_HOST> --grpc-port <OBSERVER_GRPC_PORT>
```

**NOTE:** If Fault Tolerance = 1.0 (100%), then the block is fully finalized and is part of the main chain. You may see negative values or values < 1.0 - don't consider them for now, as they don't belong to the main chain. However, it may be a sign that something is wrong (depends on network config)

7. Check the latest blocks 
Run commands for all nodes in the shard (typically validator1, validator2, validator3):
```bash
cargo run -- blocks -n <LATEST_BLOCK_COUNT> -H <NODE_HOST> --http-port <NODE_HTTP_PORT> 
```
