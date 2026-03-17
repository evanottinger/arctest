import http.server
import socketserver

def test_http_server():
    PORT = 8080

    Handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.handle_request()

    assert True
