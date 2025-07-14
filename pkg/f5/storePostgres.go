package f5

import (
	"context"
	"errors"
	"fmt"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/database"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/golog"
)

type PGX struct {
	Conn *pgxpool.Pool
	dbi  database.DB
	log  golog.MyLogger
}

func (db *PGX) Get(login string) (*User, error) {
	db.log.Debug("trace : entering Get(%v)", login)
	if !db.Exist(login) {
		msg := fmt.Sprintf(UserDoesNotExist, login)
		db.log.Warn(msg)
		return nil, errors.New(msg)
	}
	res := &User{}
	err := pgxscan.Get(context.Background(), db.Conn, res, getUser, login)
	if err != nil {
		db.log.Error(SelectFailedInNWithErrorE, "Get", err)
		return nil, err
	}
	if res == nil {
		db.log.Info(FunctionNReturnedNoResults, "Get")
		return nil, pgx.ErrNoRows
	}
	return res, nil
}

func (db *PGX) Exist(login string) bool {
	db.log.Debug("trace : entering Exist(%v)", login)
	count, err := db.dbi.GetQueryInt(existUser, login)
	if err != nil {
		db.log.Error("Exist(%v) could not be retrieved from DB. failed db.Query err: %v", login, err)
		return false
	}
	if count > 0 {
		db.log.Info("Exist(%v) id does exist  count:%v", login, count)
		return true
	} else {
		db.log.Info("Exist(%v) id does not exist count:%v", login, count)
		return false
	}
}

// NewPgxDB will instantiate a new storage of type postgres and ensure schema exist
func NewPgxDB(db database.DB, log golog.MyLogger) (Storage, error) {
	var psql PGX
	pgConn, err := db.GetPGConn()
	if err != nil {
		return nil, err
	}
	psql.Conn = pgConn
	psql.dbi = db
	psql.log = log
	var postgresVersion string
	errVersionPostgres := pgConn.QueryRow(context.Background(), getPostgresVersion).Scan(&postgresVersion)
	if errVersionPostgres != nil {
		log.Error("Unable to retrieve the postgres version,  error: %v", err)
		return nil, err
	}
	log.Info("connected to postgres database version %s", postgresVersion)
	return &psql, err
}
