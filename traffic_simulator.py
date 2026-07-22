import time
import requests
import random

API_URL = "http://127.0.0.1:5000/predict"

def generate_traffic():
    while True:
        is_attack = random.random() < 0.2
        
        if is_attack:

            duration = 0
            src_bytes = random.randint(0, 100)
            count = random.randint(200, 500)
            print(f" sending ATTACK traffic... (Count: {count})")
        else:
  
            duration = random.randint(0, 5000)
            src_bytes = random.randint(200, 10000)
            count = random.randint(1, 10)
            print(f" sending Normal traffic...")

        features = [0] * 42
        features[0] = duration
        features[4] = src_bytes
        features[22] = count

        try:
            requests.post(API_URL, json={'features': features})
        except:
            print("Server not running.")

        time.sleep(2)

if __name__ == "__main__":
    print("STARTING NETWORK TRAFFIC SIMULATION")
    print("Press Ctrl+C to stop")
    generate_traffic()