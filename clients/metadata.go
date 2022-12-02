package clients

import "github.com/mainflux/mainflux/clients/internal/apiutil"

type Metadata map[string]interface{}

// Page contains page metadata that helps navigation.
type Page struct {
	Status     uint16
	Total      uint64
	Offset     uint64
	Limit      uint64
	Level      uint64
	Name       string
	Identifier string
	OwnerID    string
	Subject    string
	Object     string
	Action     string
	Tag        string
	Metadata   Metadata
	Tags       string
}

func (pm Page) Validate() error {
	if pm.Action != "" {
		if ok := ValidateAction(pm.Action); !ok {
			return apiutil.ErrMissingPolicyAct
		}
	}
	return nil
}
