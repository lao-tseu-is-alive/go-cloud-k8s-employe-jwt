package f5

import (
	"fmt"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/database"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/golog"
)

type Storage interface {
	// Get returns the user with the specified user login.
	Get(login string) (*User, error)
	// Exist returns true only if a user with the specified login exists in store.
	Exist(login string) bool
}

func GetStorageInstanceOrPanic(dbDriver string, db database.DB, l golog.MyLogger) Storage {
	var store Storage
	var err error
	switch dbDriver {
	case "pgx":
		store, err = NewPgxDB(db, l)
		if err != nil {
			panic(fmt.Sprintf("error doing NewPgxDB(pgConn : %v", err))
		}

	default:
		panic("unsupported DB driver type")
	}
	return store
}
