from http.server import BaseHTTPRequestHandler, HTTPServer
import time


class httpHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path.startswith('/json'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"success": true, "num": 1}\n')

        elif self.path.startswith('/multiple'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"success": true, "num": 2}\n')

        elif self.path.startswith('/any/method'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"success": true, "num": 3}\n')

        elif self.path.startswith('/watch'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"success": false, "reason": "Video not found"}\n')

        elif self.path.startswith('/sleepabit'):
            try:
                time.sleep(1)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"success": true, "num": 3}\n')
            except BrokenPipeError:
                pass

        elif self.path.startswith('/delayabit'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"success": true, "num": 4}\n')

        elif self.path.startswith('/fail'):
            self.send_response(500)
            self.end_headers()

        elif self.path.startswith('/die'):
            self.send_response(500)
            self.end_headers()
            self.server.shutdown()

        else:
            self.send_response(404)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        return


def run_mock_server():
    print('Starting mock server at 127.0.0.1:8080')
    my_server = HTTPServer(('127.0.0.1', 8080), httpHandler)
    my_server.serve_forever()


if __name__ == "__main__":
    run_mock_server()
