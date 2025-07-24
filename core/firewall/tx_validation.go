package firewall

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

// SimulationStatus represents the validation lifecycle of a transaction.
type SimulationStatus int

const (
	// StatusNotSeen means the transaction has not been seen by the firewall.
	StatusNotSeen SimulationStatus = iota
	// StatusUserSimReceived means a user simulation has been received, pending block inclusion.
	StatusUserSimReceived
	// StatusMatch means the block simulation matched the user simulation successfully.
	StatusMatch
	// StatusMismatch means the block simulation did not match the user simulation.
	StatusMismatch
)

func (s SimulationStatus) String() string {
	switch s {
	case StatusNotSeen:
		return "not seen"
	case StatusUserSimReceived:
		return "user simulation received, pending validation"
	case StatusMatch:
		return "validation successful: simulation matched"
	case StatusMismatch:
		return "validation failed: simulation mismatched"
	default:
		return "unknown"
	}
}

// SimulationResult holds the outcome of a firewall validation check.
type SimulationResult struct {
	Status SimulationStatus
	// Match is true if the user-provided and block-generated simulations were equivalent.
	Match bool
	// Reason provides a human-readable explanation for a simulation mismatch.
	Reason string
}

// TxSimulationPool stores user-provided simulations and the results of firewall checks.
// It is safe for concurrent use.
type TxSimulationPool struct {
	// A mutex is necessary because this pool will be written to by the RPC handler
	// (AddUserSimulation) and read from by the miner (IsUserSimulated, CompareAndStoreResult)
	// concurrently.
	mu sync.RWMutex

	userSimulations  map[common.Hash]state.FullTransactionEvents
	blockSimulations map[common.Hash]state.FullTransactionEvents
	results          map[common.Hash]*SimulationResult
}

// NewTxSimulationPool creates and initializes a new simulation pool.
func NewTxSimulationPool() *TxSimulationPool {
	return &TxSimulationPool{
		userSimulations:  make(map[common.Hash]state.FullTransactionEvents),
		blockSimulations: make(map[common.Hash]state.FullTransactionEvents),
		results:          make(map[common.Hash]*SimulationResult),
	}
}

// AddUserSimulation stores a user-provided simulation and sets its initial status.
// This is typically called from an RPC endpoint when a user submits their simulation.
func (p *TxSimulationPool) AddUserSimulation(txHash common.Hash, simulation state.FullTransactionEvents) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.userSimulations[txHash]; exists {
		return fmt.Errorf("user simulation for tx %s already exists", txHash.Hex())
	}
	p.userSimulations[txHash] = simulation
	p.results[txHash] = &SimulationResult{
		Status: StatusUserSimReceived,
	}
	return nil
}

// IsUserSimulated checks if a transaction has a user-provided simulation and is
// intended to be protected by the firewall. This is called by the miner.
func (p *TxSimulationPool) ShouldSimulateInBlock(txHash common.Hash) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, exists := p.results[txHash]
	return exists
}

func (p *TxSimulationPool) IsTransactionSafe(txHash common.Hash, blockFTE state.FullTransactionEvents) (*SimulationResult, error) {
	return p.compareAndStoreResult(txHash, blockFTE)

}

// CompareAndStoreResult fetches a user-provided simulation, compares it against a
// new block-generated simulation, and stores the final outcome. This is called by the
// miner during block construction.
func (p *TxSimulationPool) compareAndStoreResult(txHash common.Hash, blockFTE state.FullTransactionEvents) (*SimulationResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	userFTE, exists := p.userSimulations[txHash]
	if !exists {
		return nil, fmt.Errorf("user simulation for tx %s not found", txHash.Hex())
	}

	result, exists := p.results[txHash]
	if !exists {
		// This case should ideally not happen if IsUserSimulated is checked first,
		// but we handle it defensively.
		return nil, fmt.Errorf("internal state inconsistency: result entry for tx %s not found", txHash.Hex())
	}
	// Store the block-level simulation for tracking and debugging.
	p.blockSimulations[txHash] = blockFTE

	areSimilar, err := CompareTxEvents(userFTE, blockFTE)
	if areSimilar {
		result.Status = StatusMatch
		result.Match = true
		result.Reason = ""
	} else {
		result.Status = StatusMismatch
		result.Match = false
		result.Reason = err.Error()
	}

	// For a production system, a cleanup mechanism (e.g., based on block progression)
	// would be needed to prevent this map from growing indefinitely. For the demo,
	// we keep the results in memory.
	// delete(p.userSimulations, txHash)

	return result, nil
}

// GetResult retrieves the final validation result for a transaction.
// This can be used by a debug API to return the mismatch reason.
func (p *TxSimulationPool) GetResult(txHash common.Hash) (*SimulationResult, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result, exists := p.results[txHash]
	if !exists {
		return nil, false
	}
	// Return a copy to prevent race conditions on the returned struct.
	resCopy := *result
	return &resCopy, true
}

// GetStatus retrieves the current validation status for a transaction.
func (p *TxSimulationPool) GetStatus(txHash common.Hash) SimulationStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if result, exists := p.results[txHash]; exists {
		return result.Status
	}
	return StatusNotSeen
}

// compareTxEvents checks if two sets of full transaction events are equivalent.
// It is a helper function and is not thread-safe; callers must hold the lock.
func CompareTxEvents(userFTE, blockFTE state.FullTransactionEvents) (bool, error) {
	// 1. Verify that the total number of events emitted is the same.
	if len(userFTE.EventsByContract) != len(blockFTE.EventsByContract) {
		return false, fmt.Errorf("event count mismatch: user simulation has %d events, block simulation has %d",
			len(userFTE.EventsByContract), len(blockFTE.EventsByContract))
	}

	// 2. Compare each event in order of execution.
	for i := 0; i < len(userFTE.EventsByContract); i++ {
		userContractEvent := userFTE.EventsByContract[i]
		blockContractEvent := blockFTE.EventsByContract[i]

		if ok, err := compareContractEvent(userContractEvent, blockContractEvent); !ok {
			return false, fmt.Errorf("mismatch at event index %d: %v", i, err)
		}
	}

	return true, nil
}

// compareContractEvent checks if two individual contract events are equivalent.
// It compares the emitting contract's address and the event data itself.
func compareContractEvent(userCE, blockCE state.ContractEvents) (bool, error) {
	// 1. Compare the address of the contract that emitted the event.
	if userCE.Address != blockCE.Address {
		return false, fmt.Errorf("contract address mismatch: expected %s, got %s", userCE.Address.Hex(), blockCE.Address.Hex())
	}

	// 2. Compare the content of the event.
	return compareEventData(userCE.ContractEvents, blockCE.ContractEvents)
}

// compareEventData checks if two event data payloads are equivalent.
// It compares the event signature hash and all of the event parameters.
func compareEventData(userED, blockED state.EventData) (bool, error) {
	// 1. Compare the event signature hash.
	if userED.EventSigHash != blockED.EventSigHash {
		return false, fmt.Errorf("event signature hash mismatch: expected %s, got %s", userED.EventSigHash.Hex(), blockED.EventSigHash.Hex())
	}

	// 2. Compare the number of parameters.
	if len(userED.Parameters) != len(blockED.Parameters) {
		return false, fmt.Errorf("event parameter count mismatch for event %s: expected %d, got %d",
			userED.EventSigHash.Hex(), len(userED.Parameters), len(blockED.Parameters))
	}

	// 3. Compare each parameter value.
	for i := 0; i < len(userED.Parameters); i++ {
		if userED.Parameters[i] != blockED.Parameters[i] {
			return false, fmt.Errorf("event parameter mismatch at index %d for event %s", i, userED.EventSigHash.Hex())
		}
	}

	return true, nil
}
