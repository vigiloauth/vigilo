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
	jobCount := 5
	var wg sync.WaitGroup
	executedJobs := sync.Map{}

	wg.Add(jobCount)

	scheduler := NewScheduler()

	for i := range jobCount {
		jobID := i
		scheduler.RegisterJob(jobName, func(ctx context.Context) {
			defer func() {
				if _, loaded := executedJobs.LoadOrStore(jobID, true); !loaded {
					wg.Done()
				}
			}()
		})
	}

	stopCh := make(chan struct{})
	ctx := context.Background()
	go func() {
		scheduler.StartJobs(ctx)
	}()

	wg.Wait() // Wait for all jobs to complete
	close(stopCh)

	for i := 0; i < jobCount; i++ {
		value, exists := executedJobs.Load(i)
		assert.True(t, exists, "Job %d was not executed", i)
		assert.True(t, value.(bool), "Job %d did not execute correctly", i)
	}
}

func TestScheduler_Wait(t *testing.T) {
	scheduler := NewScheduler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler.RegisterJob(jobName, func(ctx context.Context) {
		time.Sleep(100 * time.Millisecond)
	})

	go scheduler.StartJobs(ctx)

	waitChan := make(chan struct{})
	go func() {
		scheduler.Wait()
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
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Job did not respect context cancellation")
	}
}
