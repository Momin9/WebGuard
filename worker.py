import os
import redis
from rq import Worker, Queue

# Define the queues to listen to
listen = ['high', 'default', 'low']

# Get Redis URL from environment variable or fallback to localhost
redis_url = os.getenv('REDIS_URL', 'rediss://:pef6dac08015aea4a2c3a5294c083b651f8253d3c335e4a7062d42a477f39e916@ec2-35-174-24-44.compute-1.amazonaws.com:27240')

# Create a Redis connection
conn = redis.from_url(redis_url)

if __name__ == '__main__':
    # Instantiate and start the worker
    queues = [Queue(name, connection=conn) for name in listen]  # Pass connection to each Queue
    worker = Worker(queues, connection=conn)
    worker.work()
