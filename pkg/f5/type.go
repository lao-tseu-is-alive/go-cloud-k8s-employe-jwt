package f5

type User struct {
	Id       int32  `json:"user_id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"login"`
}
