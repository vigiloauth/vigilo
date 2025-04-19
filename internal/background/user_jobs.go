package background

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	domain "github.com/vigiloauth/vigilo/internal/domain/user"
)

type UserJobs struct {
	userService domain.UserService
	interval    time.Duration
	logger      *config.Logger
	module      string
}

func NewUserJobs(userService domain.UserService, interval time.Duration) *UserJobs {
	return &UserJobs{
		userService: userService,
		interval:    interval,
		logger:      config.GetServerConfig().Logger(),
		module:      "User Jobs",
	}
}

func (u *UserJobs) DeleteUnverifiedUsers(ctx context.Context) {
	u.logger.Info(u.module, "", "[DeleteUnverifiedUsers]: Starting Process of deleting unverified users that were created over a week ago")
	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			u.userService.DeleteUnverifiedUsers(ctx)
		case <-ctx.Done():
			u.logger.Info(u.module, "", "[DeleteUnverifiedUsers]: Stopping process of deleting unverified users")
			return
		}
	}
}
