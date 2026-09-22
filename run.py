import os
import sys
import subprocess
import webbrowser
import time

def check_imports():
    """
    Checks that the critical libraries are installed before running.
    """
    required_libraries = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("scapy", "scapy"),
        ("river", "river"),
        ("sklearn", "scikit-learn"),
        ("sqlalchemy", "sqlalchemy")
    ]
    
    missing = []
    for lib_import, lib_pip in required_libraries:
        try:
            __import__(lib_import)
        except ImportError:
            missing.append(lib_pip)
            
    if missing:
        print("="*60)
        print("MISSING LIBRARIES DETECTED!")
        print("Please install the required dependencies using the command:")
        print(f"  pip install {' '.join(missing)}")
        print("="*60)
        sys.exit(1)

def main():
    check_imports()
    
    # Define host and port
    host = "127.0.0.1"
    port = 8000
    
    # Print welcome block
    print("="*65)
    print("      NEXz: Network Intelligence, Education & eXploration System")
    print("           University of Ghana CS Capstone - 2026")
    print("="*65)
    print(f"Starting FastAPI dashboard backend on http://{host}:{port} ...")
    
    # Auto-open browser after the port becomes active
    def open_browser():
        import socket
        for _ in range(20):
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.5)
        time.sleep(0.5)
        print(f"Opening dashboard in default web browser: http://{host}:{port}/")
        webbrowser.open(f"http://{host}:{port}/")

    import threading
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.start()

    # Launch uvicorn server
    import uvicorn
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    main()
