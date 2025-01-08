import os
import redis
from rq import Worker, Queue

# Define the queues to listen to
listen = ['high', 'default', 'low']

# Get Redis URL from environment variable or fallback to localhost
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Create a Redis connection
conn = redis.from_url(redis_url)

if __name__ == '__main__':
    # Instantiate and start the worker
    queues = [Queue(name, connection=conn) for name in listen]  # Pass connection to each Queue
    worker = Worker(queues, connection=conn)
    worker.work()
