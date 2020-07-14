CREATE TABLE IF NOT EXISTS user (
    user_id         INTEGER  NOT NULL  PRIMARY KEY  AUTOINCREMENT
  , username        TEXT     NOT NULL  UNIQUE
  , email           TEXT     NOT NULL  UNIQUE
  , bio             TEXT     NULL
  , image           TEXT     NULL
  , password        TEXT     NOT NULL
  , salt            TEXT     NOT NULL
  , iterations      INTEGER  NOT NULL);