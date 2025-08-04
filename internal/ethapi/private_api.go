// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// PrivateAPI provides an API for block builders to access the private transaction pool
type PrivateAPI struct {
	b Backend
}

// NewPrivateAPI creates a new PrivateAPI instance
func NewPrivateAPI(b Backend) *PrivateAPI {
	return &PrivateAPI{b: b}
}

// GetPendingTransactions returns up to 10 pending transactions from the private pool
// in FIFO order. These transactions remain in the pool after being returned.
func (api *PrivateAPI) GetPendingTransactions(ctx context.Context) ([]hexutil.Bytes, error) {
	// Check if Intent Guard mode is enabled
	if !api.b.IsIntentGuardModeEnabled() {
		return nil, fmt.Errorf("private transaction pool not available: Intent Guard mode not enabled")
	}

	// Get up to 10 pending transactions
	transactions := api.b.GetPrivatePoolTransactions(10)

	// Convert transactions to raw bytes
	result := make([]hexutil.Bytes, len(transactions))
	for i, tx := range transactions {
		data, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal transaction %s: %v", tx.Hash().Hex(), err)
		}
		result[i] = data
	}

	return result, nil
}

// RemoveTransaction removes a transaction from the private pool by hash
// This should be called by block builders when transactions are finalized
func (api *PrivateAPI) RemoveTransaction(ctx context.Context, txHash common.Hash) (bool, error) {
	// Check if Intent Guard mode is enabled
	if !api.b.IsIntentGuardModeEnabled() {
		return false, fmt.Errorf("private transaction pool not available: Intent Guard mode not enabled")
	}

	// Remove the transaction
	removed := api.b.RemovePrivatePoolTransaction(txHash)
	return removed, nil
}
