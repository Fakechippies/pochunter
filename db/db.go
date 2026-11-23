package db

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

func InitDB(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}

	defer db.Close()

	initStatement := `

	CREATE TABLE IF NOT EXISTS pocs(
		cve_id TEXT NOT NULL,
		source TEXT NOT NULL,
		url TEXT NOT NULL,
		fetched_at TEXT NOT NULL,
		UNIQUE (cve_id, source, url)
	); 

	CREATE TABLE IF NOT EXISTS cves(
		id TEXT PRIMARY KEY,
		published TEXT NOT NULL,
		SUMMARY TEXT NOT NULL
	    	kev INTEGER NOT NULL DEFAULT 0,
    		epss REAL
	);

	`

}
