// Copyright (c) Magistrala
// SPDX-License-Identifier: Apache-2.0

package groups

import "errors"

var (
	// ErrInvalidStatus indicates invalid status.
	ErrInvalidStatus = errors.New("invalid groups status")

	// ErrEnableGroup indicates error in enabling group.
	ErrEnableGroup = errors.New("failed to enable group")

	// ErrDisableGroup indicates error in disabling group.
	ErrDisableGroup = errors.New("failed to disable group")

	// ErrStatusAlreadyAssigned indicated that the group has already been assigned the status.
	ErrStatusAlreadyAssigned = errors.New("status already assigned")
)
