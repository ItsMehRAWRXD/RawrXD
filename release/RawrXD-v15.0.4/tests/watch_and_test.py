#!/usr/bin/env python3
"""
RawrXD File Watcher for Continuous Testing
Automatically runs tests when source files change
"""

import os
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog not installed. Using polling mode.")
    print("Install with: pip install watchdog")


class TestRunner:
    def __init__(self, test_dir: str):
        self.test_dir = Path(test_dir)
        self.last_run = 0
        self.debounce_seconds = 2
        
    def should_run(self) -> bool:
        """Check if enough time has passed since last run"""
        current_time = time.time()
        if current_time - self.last_run >= self.debounce_seconds:
            self.last_run = current_time
            return True
        return False
    
    def run_tests(self, category: str = None):
        """Run the test suite"""
        if not self.should_run():
            return
        
        print("\n" + "=" * 60)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Running tests...")
        print("=" * 60)
        
        try:
            if category:
                result = subprocess.run(
                    ['python', 'run_parallel.py', '--category', category],
                    cwd=self.test_dir,
                    capture_output=False
                )
            else:
                result = subprocess.run(
                    ['python', 'run_parallel.py'],
                    cwd=self.test_dir,
                    capture_output=False
                )
            
            print("\n" + "=" * 60)
            if result.returncode == 0:
                print("✓ All tests passed")
            else:
                print(f"✗ Tests failed (exit code: {result.returncode})")
            print("=" * 60)
            print("\nWatching for changes... (Press Ctrl+C to stop)")
            
        except Exception as e:
            print(f"Error running tests: {e}")


class SourceChangeHandler(FileSystemEventHandler):
    def __init__(self, test_runner: TestRunner, watch_patterns=None):
        self.test_runner = test_runner
        self.watch_patterns = watch_patterns or ['.c', '.cpp', '.h', '.hpp', '.asm']
        
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        
        # Check if file matches watch patterns
        if any(str(file_path).endswith(ext) for ext in self.watch_patterns):
            # Skip certain directories
            if any(skip in str(file_path) for skip in ['.git', 'build', 'obj', 'reports']):
                return
            
            print(f"\n[Change detected] {file_path.name}")
            self.test_runner.run_tests()


def watch_with_watchdog(test_dir: Path, test_runner: TestRunner):
    """Use watchdog for efficient file watching"""
    event_handler = SourceChangeHandler(test_runner)
    observer = Observer()
    
    # Watch source directories
    watch_dirs = [
        test_dir.parent / 'src',
        test_dir.parent / 'kernels',
        test_dir,
    ]
    
    for watch_dir in watch_dirs:
        if watch_dir.exists():
            observer.schedule(event_handler, str(watch_dir), recursive=True)
            print(f"Watching: {watch_dir}")
    
    observer.start()
    
    try:
        print("\nWatching for changes... (Press Ctrl+C to stop)\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping watcher...")
        observer.stop()
    
    observer.join()


def watch_with_polling(test_dir: Path, test_runner: TestRunner, interval: int = 5):
    """Fallback polling mode when watchdog is not available"""
    print(f"\nPolling mode (interval: {interval}s)")
    print("Consider installing watchdog: pip install watchdog\n")
    
    # Track file modification times
    file_mtimes = {}
    
    watch_dirs = [
        test_dir.parent / 'src',
        test_dir.parent / 'kernels',
        test_dir,
    ]
    
    watch_patterns = ['.c', '.cpp', '.h', '.hpp', '.asm']
    
    def scan_files():
        files = {}
        for watch_dir in watch_dirs:
            if not watch_dir.exists():
                continue
            for ext in watch_patterns:
                for file_path in watch_dir.rglob(f'*{ext}'):
                    if any(skip in str(file_path) for skip in ['.git', 'build', 'obj', 'reports']):
                        continue
                    try:
                        files[str(file_path)] = file_path.stat().st_mtime
                    except:
                        pass
        return files
    
    # Initial scan
    file_mtimes = scan_files()
    
    try:
        print("Watching for changes... (Press Ctrl+C to stop)\n")
        while True:
            time.sleep(interval)
            
            current_files = scan_files()
            
            # Check for modifications
            changed = []
            for path, mtime in current_files.items():
                if path not in file_mtimes or file_mtimes[path] != mtime:
                    changed.append(Path(path).name)
            
            if changed:
                print(f"\n[Changes detected] {', '.join(changed[:3])}{'...' if len(changed) > 3 else ''}")
                test_runner.run_tests()
                file_mtimes = current_files
            
    except KeyboardInterrupt:
        print("\n\nStopping watcher...")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='RawrXD File Watcher')
    parser.add_argument('--category', '-c', help='Only run tests from specific category')
    parser.add_argument('--interval', '-i', type=int, default=5, help='Polling interval (seconds)')
    parser.add_argument('--once', '-o', action='store_true', help='Run once and exit (no watching)')
    
    args = parser.parse_args()
    
    # Find test directory
    script_dir = Path(__file__).parent
    test_dir = script_dir
    
    print("RawrXD File Watcher")
    print("=" * 60)
    print(f"Test Directory: {test_dir}")
    if args.category:
        print(f"Category: {args.category}")
    print()
    
    test_runner = TestRunner(test_dir)
    
    if args.once:
        test_runner.run_tests(args.category)
        return 0
    
    # Run initial tests
    test_runner.run_tests(args.category)
    
    # Start watching
    if WATCHDOG_AVAILABLE:
        watch_with_watchdog(test_dir, test_runner)
    else:
        watch_with_polling(test_dir, test_runner, args.interval)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
