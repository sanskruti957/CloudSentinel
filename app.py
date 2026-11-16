
from flask import Flask, render_template, Response
from pathlib import Path
import csv
import io

app = Flask(__name__)

LOG_FILE = Path(__file__).parent / "logs" / "logs.txt"


def analyze_logs():
    failed = 0
    successful = 0
    failed_logins = {}
    events = []

    if LOG_FILE.exists():
        with open(LOG_FILE, "r") as file:
            for line in file:
                parts = line.strip().split()

                if len(parts) < 3:
                    continue

                ip = parts[0]
                activity = parts[1] + " " + parts[2]

                if activity == "LOGIN FAILED":
                    failed += 1
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1

                elif activity == "LOGIN SUCCESS":
                    successful += 1

                else:
                    continue

                events.append({
                    "ip": ip,
                    "activity": activity
                })

    suspicious_ips = [
        {"ip": ip, "count": count}
        for ip, count in failed_logins.items()
        if count >= 3
    ]

    return failed, successful, suspicious_ips, events


@app.route("/")
def dashboard():
    failed, successful, suspicious_ips, events = analyze_logs()

    return render_template(
        "index.html",
        failed=failed,
        successful=successful,
        total=failed + successful,
        suspicious_ips=suspicious_ips,
        events=events
    )


@app.route("/report")
def download_report():
    failed, successful, suspicious_ips, events = analyze_logs()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["IP Address", "Activity", "Status"])

    for event in events:
        status = (
            "Failed"
            if event["activity"] == "LOGIN FAILED"
            else "Successful"
        )

        writer.writerow([
            event["ip"],
            event["activity"],
            status
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=cloudsentinel_report.csv"
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
