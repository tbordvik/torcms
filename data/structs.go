package data

type Permission struct {
	Name string
}
type User struct {
	Username string
	Perm Permission
}

func (p Permission) IsAdmin() bool {
	return p.Name == "admin"
}
