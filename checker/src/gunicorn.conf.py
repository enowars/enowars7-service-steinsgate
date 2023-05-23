# This is a configuration file required by the checker.
import multiprocessing
worker_class = "uvicorn.workers.UvicornWorker"
workers = min(4, multiprocessing.cpu_count())
bind = "0.0.0.0:3031"
timeout = 90
keepalive = 3600
preload_app = True