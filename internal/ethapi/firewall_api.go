package ethapi

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// chainContext implements the core.ChainContext interface.
type chainContext struct {
	backend Backend
}

func (c *chainContext) Engine() consensus.Engine {
	return c.backend.Engine()
}

func (c *chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	header, _ := c.backend.HeaderByNumber(context.Background(), rpc.BlockNumber(number))
	// TODO: we should have a better way to get the header by hash and number,
	// but for now this is a simple workaround.
	if header != nil && header.Hash() == hash {
		return header
	}
	header, _ = c.backend.HeaderByHash(context.Background(), hash)
	if header != nil {
		return header
	}
	return nil
}

func (c *chainContext) Config() *params.ChainConfig {
	return c.backend.ChainConfig()
}

// FirewallAPI provides an API to simulate a block of transactions with firewall validation.
type FirewallAPI struct {
	backend Backend
}

// NewFirewallAPI creates a new Firewall API instance.
func NewFirewallAPI(backend Backend) *FirewallAPI {
	return &FirewallAPI{backend: backend}
}

// FirewallAPIArgs represents the arguments for the firewall_simulateBlock RPC method.
type FirewallAPIArgs struct {
	ParentBlockHash rpc.BlockNumberOrHash `json:"parentBlockHash"`
	// Raw transaction bytes
	Transactions []hexutil.Bytes `json:"transactions"`
}

// DroppedTxInfo contains information about a transaction that was dropped during simulation.
type DroppedTxInfo struct {
	Hash   common.Hash `json:"hash"`
	Reason string      `json:"reason"`
}

// FirewallAPIResult is the return value of the firewall_simulateBlock RPC method.
type FirewallAPIResult struct {
	IncludedTxs []*types.Transaction `json:"includedTxs"`
	DroppedTxs  []*DroppedTxInfo     `json:"droppedTxs"`
}

// SimulateBlock simulates a block with a predefined list of transactions, validating
// any transactions that have a corresponding entry in the Checkpoints map.
// This function replaces the logic of runIntentGuardProtection, but in a stateless
// API-centric way.
func (api *FirewallAPI) SimulateBlock(ctx context.Context, args FirewallAPIArgs) (*FirewallAPIResult, error) {
	// 1. Get Parent Block and StateDB using the more robust method.
	statedb, parentHeader, err := api.backend.StateAndHeaderByNumberOrHash(ctx, args.ParentBlockHash)
	if err != nil {
		return nil, err
	}

	// This is the beneficiary address for the simulated block.
	// As it's just a simulation, it can be the zero address.
	coinbase := common.Address{}

	blockContext := core.NewEVMBlockContext(parentHeader, &chainContext{api.backend}, &coinbase)
	// The header for the simulated block.
	header := &types.Header{
		ParentHash: parentHeader.Hash(),
		Number:     new(big.Int).Add(parentHeader.Number, common.Big1),
		GasLimit:   parentHeader.GasLimit,
		Difficulty: common.Big1,
		Coinbase:   coinbase,
		BaseFee:    blockContext.BaseFee,
	}

	gasPool := new(core.GasPool).AddGas(header.GasLimit)
	var includedTxs []*types.Transaction
	var droppedTxs []*DroppedTxInfo

	// 3. Decode raw transaction bytes
	txs := make(types.Transactions, len(args.Transactions))
	for i, txData := range args.Transactions {
		log.Debug("SimulateBlock: Raw transaction data",
			"index", i,
			"size", len(txData),
			"first_20_bytes", fmt.Sprintf("%x", txData[:min(20, len(txData))]))

		var tx types.Transaction
		if err := tx.UnmarshalBinary(txData); err != nil {
			log.Error("SimulateBlock: Failed to unmarshal",
				"index", i,
				"error", err,
				"data_size", len(txData))
			return nil, fmt.Errorf("transaction %d is invalid: %w", i, err)
		}
		txs[i] = &tx

		log.Info("SimulateBlock: Successfully decoded transaction",
			"index", i,
			"hash", tx.Hash().Hex(),
			"nonce", tx.Nonce(),
			"to", tx.To())
	}

	// 4. Sequentially process transactions
	for i, tx := range txs {
		txHash := tx.Hash()

		// 4a. Check if this transaction requires firewall validation
		shouldSimulate := api.backend.TxSimulationPool().ShouldSimulateInBlock(txHash)
		snapshot := statedb.Snapshot()
		if shouldSimulate {
			log.Info("Firewall validation required", "index", i, "hash", txHash)
			tracer := NewEventTracer(parentHeader.Number.Uint64())
			vmConfig := vm.Config{Tracer: tracer.GetHooks()}

			// Create a sandboxed state for the dry run
			simState := statedb.Copy()
			// Create a copy of gasPool for simulation to avoid affecting main execution
			simGasPool := new(core.GasPool).AddGas(gasPool.Gas())

			// Get a correctly configured EVM instance for the simulation.
			evm := api.backend.GetEVM(ctx, simState, header, &vmConfig, &blockContext)

			// Apply the transaction using the EVM-centric function.
			_, err := core.ApplyTransaction(evm, simGasPool, simState, header, tx, &header.GasUsed)
			if err != nil {
				log.Warn("Firewall tx failed pre-simulation, dropping", "index", i, "hash", txHash, "err", err)
				droppedTxs = append(droppedTxs, &DroppedTxInfo{Hash: txHash, Reason: fmt.Sprintf("Pre-simulation failed: %v", err)})
				continue
			}

			blockFTE := tracer.GetEvents()
			isSafe, compareErr := api.backend.TxSimulationPool().IsTransactionSafe(txHash, blockFTE)
			if !isSafe.Match {
				reason := "Firewall validation failed: simulation mismatch."
				if compareErr != nil {
					reason = fmt.Sprintf("Firewall validation failed: %v", compareErr)
				}
				statedb.RevertToSnapshot(snapshot)
				log.Info("Dropping tx", "index", i, "hash", txHash, "reason", reason)
				droppedTxs = append(droppedTxs, &DroppedTxInfo{Hash: txHash, Reason: reason})
			} else {
				// execution didnt fail
				// tx similar to what user wanted.
				log.Info("Firewall validation successful", "index", i, "hash", txHash)
				includedTxs = append(includedTxs, tx)
			}
		} else {
			// 5. Apply the transaction to the main state (both simulated and non-simulated txs reach here)
			snapshot := statedb.Snapshot()
			evm := api.backend.GetEVM(ctx, statedb, header, &vm.Config{}, &blockContext)

			_, err = core.ApplyTransaction(evm, gasPool, statedb, header, tx, &header.GasUsed)
			if err != nil {
				// error so we revert to the snapshot
				log.Warn("Transaction failed during main simulation, dropping", "index", i, "hash", txHash, "err", err)
				// droppedTxs = append(droppedTxs, &DroppedTxInfo{Hash: txHash, Reason: fmt.Sprintf("Execution failed: %v", err)})
				statedb.RevertToSnapshot(snapshot)
				droppedTxs = append(droppedTxs, &DroppedTxInfo{Hash: txHash, Reason: "Tx Execution failed in the EVM, error: " + err.Error()})
			} else {
				// didnt reverted, so we keep the tx
				includedTxs = append(includedTxs, tx)
			}
		}
	}

	// 6. Finalize and return the result
	return &FirewallAPIResult{
		IncludedTxs: includedTxs,
		DroppedTxs:  droppedTxs,
	}, nil
}
