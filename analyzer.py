
failed_logins = {}

with open("logs/logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        if len(parts) < 3:
            continue

        ip = parts[0]
        activity = parts[1] + " " + parts[2]

        if activity == "LOGIN FAILED":
            if ip not in failed_logins:
                failed_logins[ip] = 0

            failed_logins[ip] += 1

print("CloudSentinel IP Monitor")
print("------------------------")

for ip, count in failed_logins.items():
    print(ip, "Failed Attempts:", count)

    if count >= 3:
        print("ALERT: Suspicious IP Detected:", ip)
