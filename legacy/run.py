import sys
import os
import time
import threading
import webbrowser
import uvicorn

def open_browser():
    time.sleep(1.2)
    try:
        webbrowser.open("http://localhost:8000")
    except Exception:
        pass

if __name__ == "__main__":
    project_dir = os.path.dirname(os.path.abspath(__file__))
    if project_dir not in sys.path:
        sys.path.insert(0, project_dir)
        
    print("=" * 65)
    print("  SENTINEL // Cyber Threat Intelligence Platform")
    print("  Web Server: http://localhost:8000")
    print("  Opening Dashboard in browser automatically...")
    print("  Press Ctrl+C in this terminal to stop the server.")
    print("=" * 65)
    
    # Launch browser automatically
    threading.Thread(target=open_browser, daemon=True).start()
    
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
