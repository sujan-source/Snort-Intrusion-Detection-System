import uvicorn
import os
import sys

# Ensure backend folder is in Python Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

if __name__ == "__main__":
    print("==================================================================")
    print("      SNORT NETWORK INTRUSION DETECTION SYSTEM (NIDS) SOC         ")
    print("==================================================================")
    
    # 1. Run database seeder if needed
    try:
        from seed_data import seed_database
        seed_database()
    except Exception as e:
        print(f"[!] Warning during DB seed: {e}")

    print("[+] Starting FastAPI Web Server & Snort Alert Engine...")
    print("[+] SOC Dashboard available at: http://127.0.0.1:8080")
    print("[+] OpenAPI / Swagger Docs at: http://127.0.0.1:8080/docs\n")

    uvicorn.run("app.main:app", host="127.0.0.1", port=8080, reload=True)
