CREATE TABLE api_user (
    api_user_id     INT            NOT NULL  PRIMARY KEY  IDENTITY
  , username        NVARCHAR(32)   NOT NULL  UNIQUE
  , email           NVARCHAR(512)  NOT NULL  UNIQUE  
  , bio             NVARCHAR(1024) NULL
  , image           NVARCHAR(1024) NULL
  , passphrase_hash CHAR(44)       NOT NULL
  , salt            CHAR(24)       NOT NULL
  , iterations      INT            NOT NULL  CHECK(iterations between 150000 and 200000)
);