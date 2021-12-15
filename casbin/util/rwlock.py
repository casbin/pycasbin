# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from threading import RLock, Condition

# This implementation was adapted from https://en.wikipedia.org/wiki/Readers%E2%80%93writer_lock


class RWLockWrite:
    """write preferring readers-wirter lock"""

    def __init__(self):
        self._lock = RLock()
        self._cond = Condition(self._lock)
        self._active_readers = 0
        self._waiting_writers = 0
        self._writer_active = False

    def aquire_read(self):
        with self._lock:
            while self._waiting_writers > 0 or self._writer_active:
                self._cond.wait()
            self._active_readers += 1

    def release_read(self):
        with self._lock:
            self._active_readers -= 1
            if self._active_readers == 0:
                self._cond.notify_all()

    def aquire_write(self):
        with self._lock:
            self._waiting_writers += 1
            while self._active_readers > 0 or self._writer_active:
                self._cond.wait()
            self._waiting_writers -= 1
            self._writer_active = True

    def release_write(self):
        with self._lock:
            self._writer_active = False
            self._cond.notify_all()

    def gen_rlock(self):
        return ReadRWLock(self)

    def gen_wlock(self):
        return WriteRWLock(self)


class ReadRWLock:
    def __init__(self, rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.aquire_read()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_read()
        return False


class WriteRWLock:
    def __init__(self, rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.aquire_write()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_write()
        return False
