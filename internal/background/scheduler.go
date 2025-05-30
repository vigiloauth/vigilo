package background

import (
	"context"
	"sync"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

type JobFunc func(ctx context.Context)

type Scheduler struct {
	mu     sync.RWMutex
	jobs   []JobFunc
	wg     sync.WaitGroup
	stopCh chan struct{}
	logger *config.Logger
	module string
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		logger: config.GetServerConfig().Logger(),
		module: "Scheduler",
		stopCh: make(chan struct{}),
	}
}

func (s *Scheduler) RegisterJob(jobName string, job JobFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, job)
	s.logger.Info(s.module, "", "[RegisterJob]: Registered job [%s]. Total jobs: %d", jobName, len(s.jobs))
}

func (s *Scheduler) StartJobs(ctx context.Context) {
	s.logger.Info(s.module, "", "[StartJobs]: Starting %d background jobs...", len(s.jobs))
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i, job := range s.jobs {
		s.wg.Add(1)
		go func(i int, j JobFunc) {
			defer s.wg.Done()
			s.logger.Info(s.module, "", "[StartJobs]: Starting job #%d", i+1)
			j(ctx)
		}(i, job)
	}

	s.wg.Wait()
	s.logger.Info(s.module, "", "[StartJobs]: All background jobs completed.")
}

func (s *Scheduler) Stop() {
	close(s.stopCh)
}

func (s *Scheduler) Wait() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger.Info(s.module, "", "Waiting for all background jobs to finish...")
	s.wg.Wait()
	s.logger.Info(s.module, "", "All background jobs have finished.")
}

func (s *Scheduler) GetJobs() []JobFunc {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jobs
}
