"""
Single Deployable Server Runner for Honeywell Cyber Operations Console.
Launches FastAPI backend + static React frontend on http://localhost:8000.
Includes fast <2s cold-boot startup (skips rebuilding frontend unless --rebuild flag is passed).
"""

import os
import sys
import subprocess
import argparse
import webbrowser
import uvicorn

def main():
    parser = argparse.ArgumentParser(description="Run Honeywell Cyber Operations Web App")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild React frontend assets before starting server")
    parser.add_argument("--port", type=int, default=8000, help="Port to serve web app (default: 8000)")
    args = parser.parse_args()

    project_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(project_dir, "frontend")
    dist_dir = os.path.join(frontend_dir, "dist")

    # Optional rebuild step if requested or if dist directory missing
    if args.rebuild or not os.path.exists(dist_dir):
        print("[BUILD] Building React frontend production bundle...")
        build_cmd = "npx vite build" if os.name != "nt" else r".\node_modules\.bin\vite build"
        res = subprocess.run(build_cmd, cwd=frontend_dir, shell=True)
        if res.returncode != 0:
            print("[ERROR] Frontend build failed. Starting backend server only.")
        else:
            print("[SUCCESS] React frontend build complete.")
    else:
        print("[FAST COLD BOOT] Using pre-built frontend bundle in frontend/dist")

    print(f"\n[STARTING] Honeywell Cyber Operations Console on http://localhost:{args.port}")
    print("Press Ctrl+C to stop the server.\n")

    # Automatically open browser
    try:
        webbrowser.open(f"http://localhost:{args.port}")
    except Exception:
        pass

    # Run Uvicorn server
    sys.path.append(project_dir)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=args.port, reload=False)

if __name__ == "__main__":
    main()
