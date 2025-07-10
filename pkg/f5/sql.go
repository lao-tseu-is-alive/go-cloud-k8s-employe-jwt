package f5

const (
	getPostgresVersion = "SELECT version();"
	countUsers         = "SELECT COUNT(*) FROM employe WHERE isactive=true;"
	existUser          = "SELECT COUNT(*) FROM employe WHERE isactive=true AND mainntlogin ilike $1;"
	getUser            = `
select  
    idemploye as user_id,
    nom || ', ' || prenom as name,
    email,
    mainntlogin as login
from employe
where
    isactive=true
    AND
    mainntlogin = $1;
`
)
