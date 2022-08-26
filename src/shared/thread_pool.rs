use std::sync::{mpsc, Arc, Mutex};
use std::thread;

/// Represents and controls a pool of OS threads, which can receive jobs (`FnOnce`
/// pointers) to be executed. Threads are spawned when the pool is created via the
/// [ThreadPool::new] constructor and terminated when the pool struct is dropped.
pub struct ThreadPool {
    label: String,
    workers: Vec<Worker>,
    sender: mpsc::Sender<WorkerMessage>,
}

impl ThreadPool {
    /// Creates and returns a new [`ThreadPool`]. The OS threads are spawned
    /// before returning from this functions. The `size` parameters controls
    /// how many threads are spawned and must be > 0.
    pub fn new(size: usize, label: &str) -> ThreadPool {
        assert!(size > 0);
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);
        for _ in 0..size {
            let receiver_clone = Arc::clone(&receiver);
            let worker = Worker::new(receiver_clone);
            workers.push(worker);
        }
        ThreadPool {
            label: label.to_string(),
            workers,
            sender,
        }
    }

    /// Provide a job to be sent to one of any threads of the [`ThreadPool`].
    /// Jobs are scheduled in a queue and executed as soon a thread is free.
    pub fn execute<F: FnOnce() + Send + 'static>(&self, function: F) {
        let job = WorkerMessage::Job(Box::new(function));
        self.sender.send(job).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        log::warn!("Shutting down '{}' thread pool.", self.label);
        for _ in &self.workers {
            self.sender.send(WorkerMessage::Stop).unwrap();
        }
        for worker in &mut self.workers {
            let thread_handle = worker.thread.take();
            if let Some(handle) = thread_handle {
                handle.join().unwrap()
            }
        }

        log::warn!("Thread pool '{}' shut down.", self.label);
    }
}

/// Represents a thread of a [`ThreadPool`]. It dequeue new jobs from
/// the receiving end of the dedicated channel. The spawned thread can
/// be stopped sending the [`WorkerMessage::Stop`] message to it.
struct Worker {
    thread: Option<thread::JoinHandle<()>>,
}

enum WorkerMessage {
    Job(Box<dyn FnOnce() + Send + 'static>),
    Stop,
}

impl Worker {
    /// Spawn an OS thread and returns a [`Worker`] containing the
    /// thread handle. The thread loops receiving and executing jobs.
    fn new(receiver: Arc<Mutex<mpsc::Receiver<WorkerMessage>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let receiver_guard = receiver.lock().unwrap();
            let worker_message = receiver_guard.recv().unwrap();
            drop(receiver_guard);
            match worker_message {
                WorkerMessage::Stop => return,
                WorkerMessage::Job(job_fn) => job_fn(),
            }
        });

        Worker { thread: Some(thread) }
    }
}
