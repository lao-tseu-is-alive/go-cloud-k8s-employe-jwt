create table if not exists public.employe
(
    idemploye       integer   not null
        constraint pk_employe
            primary key,
    idpolitesse     integer   not null,
    idfonction      integer   not null,
    codezadig       integer,
    nom             text      not null,
    prenom          text      not null,
    mainntlogin     text      not null,
    exchangelogin   text,
    initiale        text,
    datenaissance   timestamp,
    addresse        text,
    codepostal      integer,
    localite        text,
    telprive        text,
    telprof         text,
    datedebut       timestamp,
    isactive        boolean   not null,
    issexm          boolean   not null,
    datefin         timestamp,
    idbadgecalitime integer,
    tauxoccupation  integer,
    natel           text,
    idservice       integer,
    email           text      not null,
    datecreated     timestamp not null,
    datelastmodif   timestamp,
    idcreator       integer   not null,
    idlastmodifuser integer,
    timestamp       bigint,
    idmanager       integer,
    service         text,
    directionprefix text,
    comment         text,
    guidkey         uuid      not null,
    idacteur        integer,
    dateacceptcond  timestamp,
    dureeacceptcont integer
);

alter table public.employe
    owner to go_cloud_k8s_employe_jwt;

