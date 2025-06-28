package firewall

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

type TxSimulationPool struct {
	userSimulations  map[common.Hash]state.FullTransactionEvents
	blockSimulations map[common.Hash]state.FullTransactionEvents
}

func NewTxSimulationPool() *TxSimulationPool {
	return &TxSimulationPool{
		userSimulations:  make(map[common.Hash]state.FullTransactionEvents),
		blockSimulations: make(map[common.Hash]state.FullTransactionEvents),
	}
}

func (txSimulationPool *TxSimulationPool) AddUserSimulation(txHash common.Hash, simulation state.FullTransactionEvents) error {
	_, exists := txSimulationPool.userSimulations[txHash]
	if exists {
		fmt.Println("user simulation already exists")
		return fmt.Errorf("user simulation already exists")
	}
	txSimulationPool.userSimulations[txHash] = simulation
	return nil
}
func (txSimulationPool *TxSimulationPool) AddBlockSimulation(txHash common.Hash, simulation state.FullTransactionEvents) {
	txSimulationPool.blockSimulations[txHash] = simulation
}

func (txSimulationPool *TxSimulationPool) IsUserSimulated(txHash common.Hash) bool {
	_, exists := txSimulationPool.userSimulations[txHash]
	return exists
}

// Call after the verification o the simulation is done AreSimulationsSimilar
// at this time, the tx is in the block, validated by user.
// either let tx go through or remove it from the block
// then we clean the txSimulationPool
func (txSimulationPool *TxSimulationPool) CleanUp(txHash common.Hash) {
	delete(txSimulationPool.userSimulations, txHash)
	delete(txSimulationPool.blockSimulations, txHash)
}

// AreSimulationsSimilar fetches the user-provided and block-generated simulations
// for a given transaction and compares them for equivalence.
func (txSimulationPool *TxSimulationPool) AreSimulationsSimilar(txHash common.Hash) (bool, error) {
	userSimulation, exists := txSimulationPool.userSimulations[txHash]
	if !exists {
		return false, fmt.Errorf("user simulation for tx %s not found", txHash.Hex())
	}
	blockSimulation, exists := txSimulationPool.blockSimulations[txHash]
	if !exists {
		return false, fmt.Errorf("block simulation for tx %s not found", txHash.Hex())
	}

	areSimilar, err := txSimulationPool.compareTxEvents(userSimulation, blockSimulation)

	// after verification, we clean the txSimulationPool
	// TODO: will cleanup after mechanism for verifying is implemented
	// txSimulationPool.CleanUp(txHash)

	return areSimilar, err
}

// compareEvents checks if two sets of full transaction events are equivalent.
// It checks for the same number of events, and then compares each event one by one.
func (txSimulationPool *TxSimulationPool) compareTxEvents(userFTE, blockFTE state.FullTransactionEvents) (bool, error) {
	// 1. Verify that the total number of events emitted is the same.
	if len(userFTE.EventsByContract) != len(blockFTE.EventsByContract) {
		return false, fmt.Errorf("event count mismatch: user simulation has %d events, block simulation has %d",
			len(userFTE.EventsByContract), len(blockFTE.EventsByContract))
	}

	// 2. Compare each event in order of execution.
	for i := 0; i < len(userFTE.EventsByContract); i++ {
		userContractEvent := userFTE.EventsByContract[i]
		blockContractEvent := blockFTE.EventsByContract[i]

		if ok, err := txSimulationPool.compareContractEvent(userContractEvent, blockContractEvent); !ok {
			return false, fmt.Errorf("mismatch at event index %d: %v", i, err)
		}
	}

	return true, nil
}

// compareContractEvent checks if two individual contract events are equivalent.
// It compares the emitting contract's address and the event data itself.
func (txSimulationPool *TxSimulationPool) compareContractEvent(userCE, blockCE state.ContractEvents) (bool, error) {
	// 1. Compare the address of the contract that emitted the event.
	if userCE.Address != blockCE.Address {
		return false, fmt.Errorf("contract address mismatch: expected %s, got %s", userCE.Address.Hex(), blockCE.Address.Hex())
	}

	// 2. Compare the content of the event.
	// Note: The struct field is confusingly named `ContractEvents` but is of type `EventData`.
	return txSimulationPool.compareEventData(userCE.ContractEvents, blockCE.ContractEvents)
}

// compareEventData checks if two event data payloads are equivalent.
// It compares the event signature hash and all of the event parameters.
func (txSimulationPool *TxSimulationPool) ßßcompareEventData(userED, blockED state.EventData) (bool, error) {
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
