#как запускать
#переход в папку ns-3.42
#первый запуск - сборка cc (для более быстрой работы)
#./ns3 clean - если проект был сбилден до этого
#./ns3 configure
#./ns 3 build
#rm -f *.csv -- очистка csv
#python crypto5g_env.py

import subprocess
import csv
import os
import numpy as np
from itertools import product
import time

class Crypto5GEnv:
    def __init__(self, ns3_dir="./", sim_time=100, packet_size=4096, interval=0.01):
        self.ns3_dir = os.path.abspath(os.path.expanduser(ns3_dir))
        self.sim_time = sim_time
        self.packet_size = packet_size
        self.interval = interval
        self.csv_path = os.path.join(self.ns3_dir, "rl_env_step.csv")
        
        self.algorithms = ["NONE", "NEA1", "NEA2", "NEA3", "NEA7"]
        self.key_lengths = [128, 256]
        
        self.rekey_intervals = [0, 5, 10, 20]
        self.crypto_scales = [1.0, 10.0]
        
        self.exploration_actions = list(product(
            range(len(self.algorithms)),
            range(len(self.key_lengths)),
            range(len(self.rekey_intervals)),
            range(len(self.crypto_scales))
        ))
        
        self.initial_energy_j = 20000.0
        self.cumulative_drain_j = 0.0
        self.battery = 100.0
        self.security_req = 0.8
        self.current_action = None
        self.step_count = 0
        self.max_steps = 100
        self.fast_mode = False 

    def reset(self):
        self.cumulative_drain_j = 0.0
        self.battery = 100.0
        self.step_count = 0
        self.current_action = None
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)
        return self._get_state()

    def step(self, action):
        alg_idx, key_idx, rekey_idx, scale_idx = action
        algo = self.algorithms[alg_idx]
        key_len = self.key_lengths[key_idx]
        rekey_int = self.rekey_intervals[rekey_idx]
        scale = self.crypto_scales[scale_idx]
        
        self.current_action = action

        mode_str = "fast" if self.fast_mode else "ns-3"
        start_time = time.time()

        if self.fast_mode:
            metrics = self._mock_metrics(algo, key_len, rekey_int, scale)
        else:
            self._run_ns3(algo, key_len, rekey_int, scale)
            metrics = self._parse_csv()
        step_drain = metrics.get("TotalEnergyJ", 0.0)
        self.cumulative_drain_j += step_drain
        self.battery = max(0.0, (self.initial_energy_j - self.cumulative_drain_j) / self.initial_energy_j * 100.0)

        reward = self._compute_reward(metrics)
        self.step_count += 1
        done = self.step_count >= self.max_steps or self.battery <= 20.0
        
        elapsed = time.time() - start_time
        print(f"  Elapsed: {elapsed:.1f}s | Reward: {reward:.3f} | Battery: {self.battery:.2f}%")
        
        return self._get_state(), reward, done, metrics

    def _run_ns3(self, algo, key_len, rekey_int, scale):
        cmd = (
            f"cd {self.ns3_dir} && "
            f"./ns3 run 'scratch/my_5g_sim2 "
            f"--simTime={self.sim_time} "
            f"--packetSize={self.packet_size} "
            f"--udpInterval={self.interval} "
            f"--cryptoAlg={algo} "
            f"--keyLength={key_len} "
            f"--rekeyInterval={rekey_int} "
            f"--cryptoScale={scale} "
            f"--outputCsv={self.csv_path} "
            f"--RngSeed=1'"
        )
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            print("Execution failed")

    def _parse_csv(self):
        if not os.path.exists(self.csv_path):
            return None
        try:
            with open(self.csv_path, "r") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                if not rows: return None
                
                parsed = {}
                for k, v in rows[-1].items():
                    try:
                        parsed[k] = float(v)
                    except ValueError:
                        parsed[k] = v.strip()
                return parsed
        except Exception as e:
            print(f"Parse error: {e}")
            return None

    def _mock_metrics(self, algo, key_len, rekey_int, scale): #ускоренная версия
        base = {"ThroughputKbps": 3300.0, "E2EMeanDelayMs": 13.8}
        scales = {
            "NONE": {"CryptoEnergyJ": 0.0, "TotalEnergyJ": 1850.0, "SecurityScore": 0.0},
            "NEA1": {"CryptoEnergyJ": 490.0, "TotalEnergyJ": 2340.0, "SecurityScore": 0.7},
            "NEA2": {"CryptoEnergyJ": 410.0, "TotalEnergyJ": 2260.0, "SecurityScore": 0.8},
            "NEA3": {"CryptoEnergyJ": 180.0, "TotalEnergyJ": 2030.0, "SecurityScore": 0.85},
            "NEA7": {"CryptoEnergyJ": 610.0, "TotalEnergyJ": 2460.0, "SecurityScore": 0.9}
        }
        m = {**base, **scales.get(algo, {})}
        if key_len == 256:
            m["CryptoEnergyJ"] *= 1.35
            m["TotalEnergyJ"] += m["CryptoEnergyJ"] * 0.35
            m["SecurityScore"] = min(1.0, m["SecurityScore"] + 0.1)
        return m

    def _get_state(self):
        if self.current_action is None:
            a, k, r, s = 3, 0, 0, 0  
        else:
            a, k, r, s = self.current_action
        return np.array([
            self.battery / 100.0, self.security_req,
            a / (len(self.algorithms) - 1), k, r, s
        ], dtype=np.float32)

    def _compute_reward(self, m):
        tp_norm   = min(m.get("ThroughputKbps", 0) / 4000.0, 1.0)
        lat_norm  = 1.0 / (m.get("E2EMeanDelayMs", 20) / 20.0 + 0.01)
        cryp_norm = m.get("CryptoEnergyJ", 0.0) / 1000.0
        sec       = m.get("SecurityScore", 0.0)
        return 0.25*tp_norm + 0.30*lat_norm - 0.20*cryp_norm + 0.25*sec

    def get_action_desc(self, action):
        a, k, _, _ = action
        return f"{self.algorithms[a]}-{self.key_lengths[k]}b"

if __name__ == "__main__":
    env = Crypto5GEnv(ns3_dir="~/crypto_rl_project/ns-allinone-3.42/ns-3.42", sim_time=50)
    env.fast_mode = False  
    
    state = env.reset()
    print("Этап 1: Тестирование всех комбинаций")
    exploration_results = []

    for act_idx, action in enumerate(env.exploration_actions):
        if env.battery <= 20.0:
            print("Точка остановы: разряжена батарея.")
            break
            
        desc = env.get_action_desc(action)
        print(f"  ▶ [{act_idx+1:2d}/{len(env.exploration_actions)}] {desc}")
        state, reward, done, info = env.step(action)
        exploration_results.append((desc, action, reward))
        if done: break

    if exploration_results:
        best_desc, best_action, best_reward = max(exploration_results, key=lambda x: x[2])
        print(f"\nОптимальное решение: {best_desc} (Reward: {best_reward:.3f})")
        print("Этап 2: работа выбранных параметров\n")
        
        for step in range(10):
            if env.battery <= 20.0 or done:
                print(f"Точка остаановы: батарея {env.battery:.2f}% или done=True")
                break
            state, reward, done, info = env.step(best_action)
            print(f"  Шаг {step+1:2d} | {best_desc:<12} | Reward: {reward:.3f} | {env.battery:.2f}% | {info['E2EMeanDelayMs']:.2f} ms")

    print(f"\nИтоговая батарея: {env.battery:.2f}%")