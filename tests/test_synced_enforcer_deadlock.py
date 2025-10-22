# Copyright 2024 The casbin Authors. All Rights Reserved.
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

import threading
import time
import unittest
import casbin
from tests.test_enforcer import get_examples


class MockRedisWatcher:
    """Mock watcher that simulates Redis watcher behavior with mutex."""
    
    def __init__(self):
        self.mutex = threading.Lock()
        self.callback = None
        self.update_count = 0
        self.subscribe_thread = None
        self.should_stop = False
        
    def set_update_callback(self, callback):
        """Set the callback function that will be called when policy changes."""
        self.callback = callback
        
    def update(self):
        """Simulate Redis watcher update - acquires mutex and publishes."""
        with self.mutex:
            self.update_count += 1
            return True
            
    def update_for_add_policy(self, sec, ptype, rule):
        """Update for add policy."""
        return self.update()
        
    def update_for_remove_policy(self, sec, ptype, rule):
        """Update for remove policy."""
        return self.update()
        
    def update_for_add_policies(self, sec, ptype, rules):
        """Update for add policies."""
        return self.update()
        
    def update_for_remove_policies(self, sec, ptype, rules):
        """Update for remove policies."""
        return self.update()
        
    def update_for_remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """Update for remove filtered policy."""
        return self.update()
        
    def simulate_subscribe(self):
        """Simulate subscribe thread that calls callback with mutex held."""
        while not self.should_stop:
            time.sleep(0.01)  # Small delay to simulate listening
            # Simulate receiving a message and calling callback
            if self.callback:
                with self.mutex:  # Acquire mutex like Redis watcher does
                    try:
                        self.callback()
                    except Exception as e:
                        print(f"Callback error: {e}")
                        
    def start_subscribe(self):
        """Start the subscribe thread."""
        self.should_stop = False
        self.subscribe_thread = threading.Thread(target=self.simulate_subscribe, daemon=True)
        self.subscribe_thread.start()
        
    def stop_subscribe(self):
        """Stop the subscribe thread."""
        self.should_stop = True
        if self.subscribe_thread:
            self.subscribe_thread.join(timeout=1.0)
            
    def close(self):
        """Close the watcher."""
        self.stop_subscribe()


class TestSyncedEnforcerDeadlock(unittest.TestCase):
    """Test that SyncedEnforcer doesn't deadlock with watcher."""
    
    def test_no_deadlock_with_concurrent_operations(self):
        """Test that concurrent policy updates and load_policy don't cause deadlock."""
        e = casbin.SyncedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        
        # Create and attach mock watcher
        watcher = MockRedisWatcher()
        e.set_watcher(watcher)
        e.enable_auto_notify_watcher(True)
        
        # Start the subscribe thread that will call load_policy
        watcher.start_subscribe()
        
        # Give subscribe thread time to start
        time.sleep(0.05)
        
        deadlock_detected = False
        errors = []
        
        def add_policies_repeatedly():
            """Repeatedly add policies."""
            try:
                for i in range(10):
                    e.add_policy(f"user{i}", "data1", "read")
                    time.sleep(0.01)
            except Exception as ex:
                errors.append(f"add_policy error: {ex}")
                
        def remove_policies_repeatedly():
            """Repeatedly remove policies."""
            try:
                time.sleep(0.02)  # Slight offset
                for i in range(5):
                    e.remove_policy(f"user{i}", "data1", "read")
                    time.sleep(0.01)
            except Exception as ex:
                errors.append(f"remove_policy error: {ex}")
        
        # Start threads that will compete for locks
        t1 = threading.Thread(target=add_policies_repeatedly)
        t2 = threading.Thread(target=remove_policies_repeatedly)
        
        t1.start()
        t2.start()
        
        # Wait for threads with timeout to detect deadlock
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)
        
        # Check if threads completed (no deadlock)
        if t1.is_alive() or t2.is_alive():
            deadlock_detected = True
            
        # Clean up
        watcher.stop_subscribe()
        watcher.close()
        
        # Assert no deadlock occurred
        self.assertFalse(deadlock_detected, "Deadlock detected: threads didn't complete in time")
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        
        # Verify watcher was notified
        self.assertGreater(watcher.update_count, 0, "Watcher should have been notified")
        
    def test_watcher_notified_after_lock_release(self):
        """Test that watcher is notified after the lock is released."""
        e = casbin.SyncedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        
        watcher = MockRedisWatcher()
        e.set_watcher(watcher)
        e.enable_auto_notify_watcher(True)
        
        # Add a policy - watcher should be notified
        result = e.add_policy("alice", "data1", "write")
        self.assertTrue(result)
        self.assertEqual(watcher.update_count, 1)
        
        # Remove a policy - watcher should be notified
        result = e.remove_policy("alice", "data1", "write")
        self.assertTrue(result)
        self.assertEqual(watcher.update_count, 2)
        
        # Add multiple policies - watcher should be notified
        rules = [
            ["bob", "data2", "read"],
            ["charlie", "data3", "write"],
        ]
        result = e.add_policies(rules)
        self.assertTrue(result)
        self.assertEqual(watcher.update_count, 3)
        
        # Remove multiple policies - watcher should be notified
        result = e.remove_policies(rules)
        self.assertTrue(result)
        self.assertEqual(watcher.update_count, 4)
        
        watcher.close()
        
    def test_watcher_not_notified_when_disabled(self):
        """Test that watcher is not notified when auto_notify is disabled."""
        e = casbin.SyncedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        
        watcher = MockRedisWatcher()
        e.set_watcher(watcher)
        e.enable_auto_notify_watcher(False)
        
        # Add a policy - watcher should NOT be notified
        result = e.add_policy("alice", "data1", "write")
        self.assertTrue(result)
        self.assertEqual(watcher.update_count, 0)
        
        watcher.close()


if __name__ == "__main__":
    unittest.main()
