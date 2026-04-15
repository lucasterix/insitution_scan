from rq import Worker

from app.queue import redis_conn, scan_queue


def main() -> None:
    worker = Worker([scan_queue], connection=redis_conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
