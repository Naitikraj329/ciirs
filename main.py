import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.routes.cameras import router as cameras_router
from backend.routes.incidents import router as incidents_router
from backend.routes.reconstruction import router as reconstruction_router
from backend.routes.trust import router as trust_router
from backend.routes.audit import router as audit_router
from backend.routes.demo import router as demo_router
from backend.routes.upload import router as upload_router
from backend.routes.object_intelligence import router as object_intelligence_router

from backend.routes.v1_cameras import router as v1_cameras_router
from backend.routes.v1_vehicles import router as v1_vehicles_router
from backend.routes.v1_system import router as v1_system_router
from backend.routes.v1_live_cameras import router as v1_live_cameras_router
from backend.routes.v1_object_searches import router as v1_object_searches_router
from backend.database import init_db

# Initialize persistent SQLite intelligence DB
init_db()

app = FastAPI(
    title="CIIRS API",
    description="CCTV Incident Intelligence & Reconstruction System - Team PANDA (Code Yudh)",
    version="2.0.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 routes
app.include_router(v1_cameras_router)
app.include_router(v1_vehicles_router)
app.include_router(v1_live_cameras_router)
app.include_router(v1_object_searches_router)
app.include_router(v1_system_router)

# Register legacy API routes for backward compatibility
app.include_router(cameras_router)
app.include_router(incidents_router)
app.include_router(reconstruction_router)
app.include_router(trust_router)
app.include_router(audit_router)
app.include_router(demo_router)
app.include_router(upload_router)
app.include_router(object_intelligence_router)

@app.get("/api/health")
def health_check():
    return {
        "status": "ONLINE",
        "service": "CIIRS Backend Intelligence Platform",
        "version": "1.0.0",
        "team": "PANDA",
        "hackathon": "CODE YUDH",
        "ai_inference_mode": "Simulated AI / Pluggable YOLO-ByteTrack-OSNet"
    }

# Mount static files from frontend/dist
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
media_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "media"))

if os.path.exists(media_dir):
    app.mount("/media", StaticFiles(directory=media_dir), name="media")

if os.path.exists(frontend_dist):
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    async def serve_spa(full_path: str):
        if full_path.startswith("api"):
            return None
        file_path = os.path.join(frontend_dist, full_path)
        if full_path and os.path.isfile(file_path):
            return FileResponse(file_path)
        index_file = os.path.join(frontend_dist, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(index_file)
        return {"error": "Frontend build not found"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
