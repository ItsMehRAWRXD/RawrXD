import sys, time, os
os.environ.setdefault("RAWXD_BASE_URL", "https://afraid-suits-joke.loca.lt")
os.environ.setdefault("CLIENT_API_KEY", "unit-test-key-1234")
os.environ.setdefault("RAWXD_UPSTREAM_KEY", "rawrxd")
os.environ.setdefault("JOB_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/0/unit")
os.environ.setdefault("JOBS_TABLE", "unit-jobs")
sys.path.insert(0, r"F:\~dev\RawrXD_AWS_Serverless_Generative_AI\src\api")
import app

class Ctx:
    def get_remaining_time_in_millis(self): return 5000
t0 = time.time()
try:
    app.bounded_upstream("/nowhere", configured_timeout=20, context=Ctx(), retries=2)
except Exception as e:
    print(f"CASE1 elapsed={time.time()-t0:.1f}s: {type(e).__name__}")

class Ctx2:
    def get_remaining_time_in_millis(self): return 100
t1 = time.time()
try:
    app.bounded_upstream("/nowhere", configured_timeout=24, context=Ctx2(), retries=2)
    print("CASE2 UNEXPECTED SUCCESS")
except app.BudgetExhausted:
    print(f"CASE2 BudgetExhausted after {time.time()-t1:.1f}s (bounded)")
except Exception as e:
    print(f"CASE2 {type(e).__name__} after {time.time()-t1:.1f}s")

t2 = time.time()
try:
    app.bounded_upstream("/nowhere", configured_timeout=24, total_budget_s=1.0, retries=2)
except Exception as e:
    print(f"CASE3 fallback {type(e).__name__} after {time.time()-t2:.1f}s")
print("UNIT_OK")
