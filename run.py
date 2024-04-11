import multiprocessing
import subprocess
import sys
import time


def run_script(port, boolean):
    subprocess.run([sys.executable, "rest.py", "-p", str(port), "-b", boolean])


if __name__ == "__main__":
    processes = []

    try:
        p1 = multiprocessing.Process(target=run_script, args=(5000, "True"))
        p1.start()
        processes.append(p1)

        time.sleep(2)

        configs = [
            (5001, "False"),
            (5002, "False"),
            (5003, "False"),
            (5004, "False"),
            # (5005, "False"),
            # (5006, "False"),
            # (5007, "False"),
            # (5008, "False"),
            # (5009, "False"),
        ]
        for port, boolean in configs:
            p = multiprocessing.Process(target=run_script, args=(port, boolean))
            p.start()
            processes.append(p)
            time.sleep(1)

        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, terminating processes")
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()

        sys.exit(1)
