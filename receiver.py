from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import datetime

class SOCEventHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            event = json.loads(raw_body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        soc_event = {
            "received_at": datetime.datetime.utcnow().isoformat(),
            "source_ip": self.client_address[0],
            "event": event
        }

        # 🔒 In real Phase 3: persist to PostgreSQL / SIEM
        print("\n📘 SOC EVENT RECEIVED")
        print(json.dumps(soc_event, indent=2))

        self.send_response(200)
        self.end_headers()

def run():
    server = HTTPServer(("0.0.0.0", 9000), SOCEventHandler)
    print("SOC Event Receiver listening on :9000")
    server.serve_forever()

if __name__ == "__main__":
    run()
