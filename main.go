package authing

import (
	"fmt"

	_ "github.com/kmlixh/gom/v4/factory/postgres" // gom PostgreSQL驱动注册
)

func init() {
	fmt.Println("Authing library initialized")
}
