import sys
import os
import time
import socket
import threading
import webbrowser
import uvicorn

def find_available_port(preferred_ports=(8000, 8080, 8001, 8088)):
    for port in preferred_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    return 8080

def open_browser(port):
    time.sleep(1.5)
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

if __name__ == "__main__":
    project_dir = os.path.dirname(os.path.abspath(__file__))
    if project_dir not in sys.path:
        sys.path.insert(0, project_dir)
        
    port = find_available_port()
    
    print("=" * 65)
    print("  SENTINEL // Cyber Threat Intelligence Platform")
    print(f"  Web Server: http://localhost:{port}")
    print("  Opening Dashboard in your browser automatically...")
    print("  Press Ctrl+C in this terminal to stop the server.")
    print("=" * 65)
    
    # Launch default browser automatically
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, reload=False)
