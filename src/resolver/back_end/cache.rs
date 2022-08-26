use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::{thread, time};

/// The cache configuration parameters used to instantiate a new
/// [`Cache`]. A Default trait implementation is provided.
pub struct CacheConf {
    pub clean_period: time::Duration,
    pub max_cleaned: u64,
}

impl Default for CacheConf {
    fn default() -> Self {
        CacheConf {
            clean_period: time::Duration::new(60, 0),
            max_cleaned: 500,
        }
    }
}

/// A thread-safe multi-purpose in-memory cache. It is generic over the
/// key and values used, but note that some bounds are necessary to
/// perform even basic operations (e.g. Eq + Hash on the key).
pub struct Cache<K, V> {
    data: Mutex<HashMap<K, (time::Instant, V)>>,
    conf: CacheConf,
}

impl<K, V> Default for Cache<K, V> {
    fn default() -> Self {
        Cache {
            data: Mutex::new(HashMap::new()),
            conf: CacheConf::default(),
        }
    }
}

impl<K: Eq + Hash, V> Cache<K, V> {
    /// Creates a new [Cache] with the provided [`CacheConf`].
    pub fn new(conf: CacheConf) -> Self {
        Cache {
            data: Mutex::new(HashMap::new()),
            conf: conf,
        }
    }

    /// Executes the given closure passing a mutable reference to the entry
    /// corresponding to the passed key. If the entry for the key isn't found
    /// the closure is not ran and false is returned.   
    pub fn on_found<BK, F>(&self, key: &BK, callback: F) -> bool
    where
        F: FnOnce(&time::Instant, &mut V),
        K: Borrow<BK>,
        BK: Eq + Hash,
    {
        let mut cache_guard = self.data.lock().unwrap();
        let cache_inner = cache_guard.deref_mut();
        let entry = match cache_inner.get_mut(key) {
            None => return false,
            Some(entry) => entry,
        };
        if is_expired(&entry.0) {
            cache_inner.remove(key);
            return false;
        }
        callback(&entry.0, &mut entry.1);
        true
    }

    /// Set the passed value overwriting and returning the previous one for that
    /// key, if any. Expired entries not yet removed are not considered and not returned.
    pub fn set(&self, key: K, ttl: time::Duration, val: V) -> Option<(time::Instant, V)> {
        let mut cache_guard = self.data.lock().unwrap();
        let cache_inner = cache_guard.deref_mut();
        let entry = (time::Instant::now() + ttl, val);
        let removed = cache_inner.insert(key, entry)?;
        match is_expired(&removed.0) {
            false => Some(removed),
            true => None,
        }
    }

    /// Removes the value at the given key, if any. The removed value is returned.
    /// Expired entries not yet removed, are not considered and not returned.
    pub fn remove(&self, key: &K) -> Option<(time::Instant, V)> {
        let mut cache_guard = self.data.lock().unwrap();
        let cache_inner = cache_guard.deref_mut();
        let entry = cache_inner.remove(key)?;
        match is_expired(&entry.0) {
            false => Some(entry),
            true => None,
        }
    }

    /// Manually cleans the cache from expired entries. Usually this method is
    /// not invoked since the [start_clean_routine] is more ergonomic to use.
    pub fn clean(&self) {
        let mut cache_guard = self.data.lock().unwrap();
        let cache_inner = cache_guard.deref_mut();
        cache_inner.retain(|_, entry| !is_expired(&entry.0));
    }
}

impl<K: Eq + Hash, V: Clone> Cache<K, V> {
    /// Clone and return the value at the given key. The method is
    /// available only for [Cache]s where the value implements [Clone].
    pub fn get_clone<BK>(&self, key: &BK) -> Option<(time::Instant, V)>
    where
        K: Borrow<BK>,
        BK: Eq + Hash,
    {
        let mut cache_guard = self.data.lock().unwrap();
        let cache_inner = cache_guard.deref_mut();
        let entry = cache_inner.get(key)?;
        match is_expired(&entry.0) {
            false => Some(entry.clone()),
            true => {
                cache_inner.remove(key);
                None
            }
        }
    }
}

impl<K: Eq + Hash + Send + 'static, V: Send + 'static> Cache<K, V> {
    /// Spawns a thread which cleans the [Cache] entries at regular
    /// periods of time (dictated by the confs).
    pub fn start_clean_routine(self: &Arc<Self>) -> thread::JoinHandle<()> {
        let period = self.conf.clean_period;
        let cache = Arc::clone(self);
        thread::spawn(move || loop {
            thread::sleep(period);
            cache.clean();
            log::info!("Cache cleaned.")
        })
    }
}

/// The [Debug] implementation of the cache should be used REALLY only
/// for debugging purposes. Printing the entire cache could be slow.
impl<K: Debug, V: Debug> Debug for Cache<K, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut cache_guard = self.data.lock().unwrap();
        let cache_inner = cache_guard.deref_mut();
        for entry in cache_inner {
            writeln!(f, "{:?}", entry)?;
        }
        Ok(())
    }
}

fn is_expired(instant: &time::Instant) -> bool {
    instant <= &time::Instant::now()
}

#[allow(dead_code)]
fn compile_time_checks() {
    fn check_send<T: Send>(_: T) {}
    fn check_sync<T: Sync>(_: T) {}
    check_send(Cache::<(), ()>::default());
    check_sync(Cache::<(), ()>::default());
}
