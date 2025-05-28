package background

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const jobName string = "test job"

func TestScheduler_RegisterJob(t *testing.T) {
	scheduler := NewScheduler()
	initialJobCount := len(scheduler.GetJobs())

	scheduler.RegisterJob(jobName, func(ctx context.Context) {
		// Register Empty job
	})

	assert.Len(t, scheduler.GetJobs(), initialJobCount+1, "RegisterJob should increase the job count by 1")
}

func TestScheduler_StartJobs(t *testing.T) {
	t.Run("Start single job", func(t *testing.T) {
		scheduler := NewScheduler()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		jobExecuted := false
		var mu sync.Mutex

		scheduler.RegisterJob(jobName, func(ctx context.Context) {
			mu.Lock()
			jobExecuted = true
			mu.Unlock()
		})

		scheduler.StartJobs(ctx)

		mu.Lock()
		assert.True(t, jobExecuted, "The registered job should have been executed")
		mu.Unlock()
	})

	t.Run("Start multiple jobs", func(t *testing.T) {
		scheduler := NewScheduler()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		jobCount := 5
		var executedJobs sync.Map
		var wg sync.WaitGroup
		wg.Add(jobCount)

		for i := 0; i < jobCount; i++ {
			jobID := i
			scheduler.RegisterJob(jobName, func(ctx context.Context) {
				defer wg.Done()
				executedJobs.Store(jobID, true)
			})
		}

		go scheduler.StartJobs(ctx)
		wg.Wait()

		for i := range jobCount {
			value, exists := executedJobs.Load(i)
			assert.True(t, exists, "Job %d should have been executed", i)
			assert.True(t, value.(bool), "Job %d should have been executed successfully", i)
		}
	})
}

func TestScheduler_Wait(t *testing.T) {
	scheduler := NewScheduler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a job that takes some time to complete
	scheduler.RegisterJob(jobName, func(ctx context.Context) {
		time.Sleep(100 * time.Millisecond)
	})

	go scheduler.StartJobs(ctx)

	waitChan := make(chan struct{})
	go func() {
		scheduler.Wait() // This should block until all jobs complete
		close(waitChan)
	}()

	select {
	case <-waitChan:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Wait did not return after jobs completed")
	}
}

func TestScheduler_ContextCancellation(t *testing.T) {
	scheduler := NewScheduler()
	ctx, cancel := context.WithCancel(context.Background())

	jobStarted := make(chan struct{})
	jobFinished := make(chan struct{})

	scheduler.RegisterJob(jobName, func(ctx context.Context) {
		close(jobStarted)
		select {
		case <-ctx.Done():
			// Job interrupted by context cancellation
		case <-time.After(5 * time.Second):
			t.Errorf("Job should have been interrupted by context cancellation")
		}
		close(jobFinished)
	})

	go scheduler.StartJobs(ctx)
	<-jobStarted
	cancel()

	select {
	case <-jobFinished:
		// Job finished after context cancellation, as expected
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Job did not respect context cancellation")
	}
}
