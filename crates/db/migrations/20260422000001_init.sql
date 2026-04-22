CREATE TABLE User (
  Username          TEXT NOT NULL,
  UserServerPrivEnc BLOB NOT NULL,
  UserServerPub     BLOB NOT NULL,
  PRIMARY KEY (Username)
);

CREATE TABLE Project (
  Projectname TEXT NOT NULL,
  PRIMARY KEY (Projectname)
);

CREATE TABLE UserProject (
  Username    TEXT NOT NULL REFERENCES User(Username) ON DELETE CASCADE,
  Projectname TEXT NOT NULL REFERENCES Project(Projectname) ON DELETE CASCADE,
  PRIMARY KEY (Username, Projectname)
);

CREATE TABLE Permission (
  Username    TEXT NOT NULL REFERENCES User(Username) ON DELETE CASCADE,
  Projectname TEXT NOT NULL REFERENCES Project(Projectname) ON DELETE CASCADE,
  KeyId       TEXT NOT NULL,
  ValueEnc    BLOB NOT NULL,
  IsOwner     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (Username, Projectname, KeyId)
);

CREATE UNIQUE INDEX OneOwnerPerKey
  ON Permission(Projectname, KeyId)
  WHERE IsOwner = 1;
