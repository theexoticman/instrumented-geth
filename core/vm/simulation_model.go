package vm

import (
	"encoding/json"
	"fmt"
)

// Simulation represents the top-level simulation output.
type Simulation struct {
	TransactionHash string  `json:"transactionHash"`
	From            string  `json:"from"`
	To              string  `json:"to"`
	GasUsed         uint64  `json:"gasUsed"`
	Status          string  `json:"status"`
	Events          []Event `json:"events"`
}

// Event represents an execution event node within the simulation tree.
type Event struct {
	Id            string                 `json:"id"`            // id of the event in the simulation.
	Type          string                 `json:"type"`          // e.g., delegatecall, ethTransfer, fallbackTriggered.
	Caller        string                 `json:"caller"`        // The contract or EOA that triggered this action.
	Target        string                 `json:"target"`        // The contract being interacted with.
	CallerContext string                 `json:"callerContext"` // The storage context of execution (for delegatecall).
	Parameters    map[string]interface{} `json:"parameters"`    // Additional event-specific data.
}

// NewEthTransferEvent creates an event for ETH transfers.
func NewEthTransferEvent(caller, receiver, value string) Event {
	return Event{
		Type:          "ethTransfer",
		Caller:        caller,
		Target:        receiver, // Receiver stored in Target.
		CallerContext: caller,
		Parameters: map[string]interface{}{
			"value": value, // Amount in wei.
		},
	}
}

// NewDelegateCallEvent creates an event for delegate calls.
func NewDelegateCallEvent(caller, target, functionSignature, data string) Event {
	return Event{
		Type:          "delegatecall",
		Caller:        caller,
		Target:        target,
		CallerContext: caller,
		Parameters: map[string]interface{}{
			"functionSignature": functionSignature, // Function selector.
			"data":              data,              // Calldata payload.
		},
	}
}

// NewFallbackTriggeredEvent creates an event for fallback/receive function triggers.
func NewFallbackTriggeredEvent(caller, target, value, data, expectedFunctionSelector string) Event {
	return Event{
		Type:          "fallbackTriggered",
		Caller:        caller,
		Target:        target,
		CallerContext: target, // For fallback, context is usually the target contract.
		Parameters: map[string]interface{}{
			"value":                    value, // ETH sent (in wei).
			"data":                     data,  // Calldata.
			"expectedFunctionSelector": expectedFunctionSelector,
		},
	}
}

// NewContractSelfDestructedEvent creates an event for contract self-destruction.
func NewContractSelfDestructedEvent(caller, beneficiary string) Event {
	return Event{
		Type:          "contractSelfDestructed",
		Caller:        caller,
		Target:        "", // No target contract.
		CallerContext: caller,
		Parameters: map[string]interface{}{
			"beneficiary": beneficiary, // Recipient of remaining balance.
		},
	}
}

// NewCreate2DeployedEvent creates an event for CREATE2 deployments.
func NewCreate2DeployedEvent(creator, newContract, salt, bytecodeHash string) Event {
	return Event{
		Type:          "create2Deployed",
		Caller:        creator,
		Target:        newContract,
		CallerContext: creator,
		Parameters: map[string]interface{}{
			"salt":         salt,         // Salt for deterministic deployment.
			"bytecodeHash": bytecodeHash, // Keccak256 hash of the deployed bytecode.
		},
	}
}

func getExample() {
	// Example events based on your specifications.
	ethTransferEvent := NewEthTransferEvent("0xUser", "0xReceiver", "1000000000000000000")
	delegateCallEvent := NewDelegateCallEvent("0xCallerContract", "0xTargetContract", "0xa9059cbb", "0xdeadbeef")
	fallbackEvent := NewFallbackTriggeredEvent("0xUnknown", "0xContract", "1000000000000000", "0xdeadbeef", "0xa9059cbb")
	selfDestructEvent := NewContractSelfDestructedEvent("0xContract", "0xReceiver")
	create2Event := NewCreate2DeployedEvent("0xDeployer", "0xDeployedContract", "0x1234...", "0xhash...")

	// Sample simulation data.
	sim := Simulation{
		TransactionHash: "0xabc123...",
		From:            "0xUserEOA",
		To:              "0xTargetContract",
		GasUsed:         210000,
		Status:          "success",
		Events: []Event{
			{
				Id:            "1",
				Type:          "ethTransfer",
				Caller:        "0xCaller",
				Target:        "0xTarget",
				CallerContext: "0xCallerContext",
				Parameters: map[string]interface{}{
					"amount": "1000",
				},
			},

			{
				Id:            "2",
				Type:          "delegatecall",
				Caller:        "0xSubCaller",
				Target:        "0xSubTarget",
				CallerContext: "0xSubCallerContext",
				Parameters: map[string]interface{}{
					"data": "0xdeadbeef",
				},
			},
			ethTransferEvent,
			delegateCallEvent,
			fallbackEvent,
			selfDestructEvent,
			create2Event,
		},
	}

	// Marshal to JSON for demonstration.
	jsonData, err := json.MarshalIndent(sim, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling simulation:", err)
		return
	}

	fmt.Println(string(jsonData))
}
