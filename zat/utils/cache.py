"""Cache class for key/value pairs"""

import time
from collections import OrderedDict
import pickle
import atexit

# Local imports
from zat.utils import file_storage


class Cache(object):
    """In process memory cache. Not thread safe.
       Usage:
            cache = Cache(max_size=5, timeout=10)
            cache.set('foo', 'bar')
            cache.get('foo')
            >>> bar
            time.sleep(11)
            cache.get('foo')
            >>> None
            cache.clear()
    """
    def __init__(self, max_size=1000, timeout=None, load=None):
        """Cache Initialization"""
        self.disk_storage = file_storage.FileStorage()
        self.load = load
        storage_bytes = None
        if load:
            storage_bytes = self.disk_storage.get(load)  # This can fail, returning None
        self.store = pickle.loads(storage_bytes) if storage_bytes else OrderedDict()
        self.max_size = max_size
        self.timeout = timeout
        self._compression_timer = 60
        self._last_compression = time.time()

        # Try to do cleanup/serialization at exit
        atexit.register(self.cleanup)

    def set(self, key, value):
        """Add an item to the cache
        Args:
               key: item key
               value: the value associated with this key
        """
        self._check_limit()
        _expire = time.time() + self.timeout if self.timeout else None
        self.store[key] = (value, _expire)

    def get(self, key):
        """Get an item from the cache
           Args:
               key: item key
           Returns:
               the value of the item or None if the item isn't in the cache
        """
        data = self.store.get(key)
        if not data:
            return None
        value, expire = data
        if expire and time.time() > expire:
            del self.store[key]
            return None
        return value

    def clear(self):
        """Clear the cache"""
        self.store = OrderedDict()

    def dump(self):
        """Dump the cache (for debugging)"""
        for key in self.store.keys():
            print(key, ':', self.get(key))

    @property
    def size(self):
        return len(self.store)

    def cleanup(self):
        print('Calling cleanup...')
        self.persist()

    def persist(self):
        """Serialize the cache to disk"""
        if self.load:
            store_bytes = pickle.dumps(self.store)
            self.disk_storage.store(self.load, store_bytes)

    def _check_limit(self):
        """Intenal method: check if current cache size exceeds maximum cache
           size and pop the oldest item in this case"""

        # First compress
        self._compress()

        # Then check the max size
        if len(self.store) >= self.max_size:
            self.store.popitem(last=False)  # FIFO

    def _compress(self):
        """Internal method to compress the cache. This method will
           expire any old items in the cache, making the cache smaller"""

        # Don't compress too often
        now = time.time()
        if self._last_compression + self._compression_timer < now:
            self._last_compression = now
            for key in list(self.store.keys()):
                self.get(key)


def test():
    """Test for the Cache class"""

    # Create the Cache
    my_cache = Cache(max_size=5, timeout=1)
    my_cache.set('foo', 'bar')

    # Test storage
    assert my_cache.get('foo') == 'bar'

    # Test timeout
    time.sleep(1.1)
    assert my_cache.get('foo') is None

    # Test max_size
    my_cache = Cache(max_size=5)
    for i in range(6):
        my_cache.set(str(i), i)

    # So the '0' key should no longer be there FIFO
    assert my_cache.get('0') is None
    assert my_cache.get('5') is not None

    # Make sure size is working
    assert my_cache.size == 5

    # Dump the cache
    my_cache.dump()

    # Test storing 'null' values
    my_cache.set(0, 'foo')
    my_cache.set(0, 'bar')
    my_cache.set(None, 'foo')
    my_cache.set('', None)
    assert my_cache.get('') is None
    assert my_cache.get(None) == 'foo'
    assert my_cache.get(0) == 'bar'

    # Test the cache compression
    my_cache = Cache(max_size=5, timeout=1)
    for i in range(5):
        my_cache.set(str(i), i)
    my_cache._compression_timer = 1
    assert my_cache.size == 5

    # Make sure compression is working
    time.sleep(1.1)
    my_cache._compress()
    assert my_cache.size == 0

    # Also make sure compression call is throttled
    my_cache._compress()  # Should not output a compression message

    # Test persistance functionality
    my_cache = Cache(load='my_test_cache')
    for i in range(5):
        my_cache.set(str(i), i)
    assert my_cache.size == 5

    my_cache.persist()
    del my_cache

    load_cache = Cache(load='my_test_cache')
    assert load_cache.size == 5
    load_cache.dump()


if __name__ == '__main__':

    # Run the test
    test()
