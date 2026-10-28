import os
import sqlite3
import json
import time
import hashlib
from typing import List, Dict, Any, Optional

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "ciirs_intelligence.db"))

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cur = conn.cursor()

    # 1. Cameras table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cameras (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'online',
        fps REAL NOT NULL DEFAULT 25.0,
        resolution TEXT NOT NULL DEFAULT '1080p',
        latency_ms INTEGER NOT NULL DEFAULT 40,
        trust_score REAL NOT NULL DEFAULT 98.0,
        is_tampered INTEGER NOT NULL DEFAULT 0,
        tamper_reason TEXT,
        lat REAL NOT NULL DEFAULT 28.6139,
        lng REAL NOT NULL DEFAULT 77.2090,
        stream_url TEXT,
        video_url TEXT,
        image_url TEXT,
        tags TEXT DEFAULT '[]',
        is_uploaded INTEGER DEFAULT 0,
        video_path TEXT,
        duration_sec REAL DEFAULT 0.0,
        created_at REAL NOT NULL
    )
    """)

    # 2. Video Assets table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS video_assets (
        id TEXT PRIMARY KEY,
        camera_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        filesize_bytes INTEGER NOT NULL,
        duration_sec REAL NOT NULL,
        fps REAL NOT NULL,
        resolution TEXT NOT NULL,
        codec TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ready',
        is_prerecorded INTEGER DEFAULT 1,
        created_at REAL NOT NULL,
        FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE
    )
    """)

    # 3. Processing Jobs table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS processing_jobs (
        id TEXT PRIMARY KEY,
        camera_id TEXT NOT NULL,
        video_id TEXT,
        status TEXT NOT NULL DEFAULT 'queued',
        progress_pct REAL NOT NULL DEFAULT 0.0,
        frames_total INTEGER NOT NULL DEFAULT 0,
        frames_processed INTEGER NOT NULL DEFAULT 0,
        detections_count INTEGER NOT NULL DEFAULT 0,
        plates_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        started_at REAL,
        completed_at REAL,
        created_at REAL NOT NULL,
        FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE
    )
    """)

    # 4. Vehicle Detections table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vehicle_detections (
        id TEXT PRIMARY KEY,
        camera_id TEXT NOT NULL,
        video_id TEXT,
        job_id TEXT,
        frame_number INTEGER NOT NULL,
        timestamp_sec REAL NOT NULL,
        vehicle_class TEXT NOT NULL,
        confidence REAL NOT NULL,
        bbox_json TEXT NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE
    )
    """)

    # 5. Number Plate Recognition (ANPR) records table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS plate_detections (
        id TEXT PRIMARY KEY,
        camera_id TEXT NOT NULL,
        video_id TEXT,
        detection_id TEXT,
        frame_number INTEGER NOT NULL,
        timestamp_sec REAL NOT NULL,
        plate_number TEXT NOT NULL,
        raw_ocr_text TEXT NOT NULL,
        ocr_confidence REAL NOT NULL,
        vehicle_class TEXT NOT NULL,
        vehicle_confidence REAL NOT NULL,
        plate_crop_path TEXT,
        db_match_status TEXT NOT NULL DEFAULT 'no_match',
        verification_status TEXT NOT NULL DEFAULT 'unverified',
        operator_notes TEXT,
        created_at REAL NOT NULL,
        FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE
    )
    """)

    # 6. Fictional Vehicle Records (Demo Provider A Database)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vehicle_records (
        registration_number TEXT PRIMARY KEY,
        owner_name TEXT NOT NULL,
        vehicle_make TEXT NOT NULL,
        vehicle_model TEXT NOT NULL,
        vehicle_class TEXT NOT NULL,
        color TEXT NOT NULL,
        fuel_type TEXT NOT NULL,
        registration_date TEXT NOT NULL,
        registration_state TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        is_stolen INTEGER NOT NULL DEFAULT 0,
        is_demo_data INTEGER NOT NULL DEFAULT 1,
        last_updated REAL NOT NULL
    )
    """)

    # 7. Challans table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS challans (
        id TEXT PRIMARY KEY,
        registration_number TEXT NOT NULL,
        challan_number TEXT NOT NULL UNIQUE,
        date_time TEXT NOT NULL,
        location TEXT NOT NULL,
        violation TEXT NOT NULL,
        penalty_amount INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'UNPAID',
        camera_id TEXT,
        evidence_url TEXT,
        created_at REAL NOT NULL,
        FOREIGN KEY (registration_number) REFERENCES vehicle_records(registration_number) ON DELETE CASCADE
    )
    """)

    # 8. Watchlist table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS watchlist (
        id TEXT PRIMARY KEY,
        registration_number TEXT NOT NULL UNIQUE,
        reason TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'HIGH',
        listed_by TEXT NOT NULL,
        added_at REAL NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # 9. Vehicle Alerts table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vehicle_alerts (
        id TEXT PRIMARY KEY,
        registration_number TEXT NOT NULL,
        plate_detection_id TEXT,
        camera_id TEXT NOT NULL,
        timestamp_sec REAL NOT NULL,
        alert_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        plate_crop_path TEXT,
        match_source TEXT NOT NULL DEFAULT 'DEMO_WATCHLIST',
        confidence REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at REAL NOT NULL,
        resolved_by TEXT,
        resolved_at REAL,
        operator_notes TEXT,
        FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE
    )
    """)

    # 10. Operator Actions Audit table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS operator_actions (
        id TEXT PRIMARY KEY,
        operator_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        details_json TEXT NOT NULL,
        timestamp REAL NOT NULL
    )
    """)

    # 11. System Audit Logs table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        user TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        module TEXT NOT NULL,
        status TEXT NOT NULL,
        details TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        hash_signature TEXT NOT NULL
    )
    """)

    # 12. Object Searches table (AI Visual Re-ID)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS object_searches (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        reference_image_path TEXT NOT NULL,
        reference_crop_path TEXT,
        target_class TEXT NOT NULL DEFAULT 'any',
        roi_bbox_json TEXT,
        similarity_threshold REAL NOT NULL DEFAULT 0.65,
        status TEXT NOT NULL DEFAULT 'active',
        active_cameras_json TEXT NOT NULL DEFAULT '["CAM-LIVE-01", "CAM-LIVE-02", "CAM-LIVE-03"]',
        total_frames_searched INTEGER NOT NULL DEFAULT 0,
        matches_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        created_at REAL NOT NULL,
        stopped_at REAL
    )
    """)

    # 13. Object Matches table (Evidence & Verification)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS object_matches (
        id TEXT PRIMARY KEY,
        search_id TEXT NOT NULL,
        camera_id TEXT NOT NULL,
        camera_name TEXT NOT NULL,
        timestamp_sec REAL NOT NULL,
        frame_number INTEGER NOT NULL DEFAULT 0,
        object_class TEXT NOT NULL,
        detection_confidence REAL NOT NULL,
        similarity_score REAL NOT NULL,
        bbox_json TEXT NOT NULL,
        reference_crop_path TEXT NOT NULL,
        match_crop_path TEXT NOT NULL,
        frame_image_path TEXT,
        video_url TEXT,
        verification_status TEXT NOT NULL DEFAULT 'unreviewed',
        operator_notes TEXT,
        verified_by TEXT,
        verified_at REAL,
        created_at REAL NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (search_id) REFERENCES object_searches(id) ON DELETE CASCADE
    )
    """)

    # Create Indexes for fast querying
    cur.execute("CREATE INDEX IF NOT EXISTS idx_plate_detections_plate ON plate_detections(plate_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_plate_detections_camera ON plate_detections(camera_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_plate_detections_time ON plate_detections(timestamp_sec)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vehicle_alerts_plate ON vehicle_alerts(registration_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_challans_plate ON challans(registration_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_watchlist_plate ON watchlist(registration_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_jobs_camera ON processing_jobs(camera_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_object_matches_search ON object_matches(search_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_object_matches_camera ON object_matches(camera_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_object_matches_status ON object_matches(verification_status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_object_matches_time ON object_matches(timestamp_sec)")

    conn.commit()

    # Seed Baseline Cameras if empty
    cur.execute("SELECT COUNT(*) FROM cameras")
    if cur.fetchone()[0] == 0:
        seed_baseline_cameras(cur)
        conn.commit()

    # Seed Demo Vehicle Records if empty
    cur.execute("SELECT COUNT(*) FROM vehicle_records")
    if cur.fetchone()[0] == 0:
        seed_demo_vehicles(cur)
        conn.commit()

    # Seed Demo Plate Detections & Alerts if empty
    cur.execute("SELECT COUNT(*) FROM plate_detections")
    if cur.fetchone()[0] < 3:
        seed_demo_detections_and_alerts(cur)
        conn.commit()

    # Seed Demo Object Searches & Matches if empty
    cur.execute("SELECT COUNT(*) FROM object_searches")
    if cur.fetchone()[0] == 0:
        seed_demo_object_searches(cur)
        conn.commit()

    conn.close()
    print("[Database] CIIRS SQLite Intelligence Database initialized successfully.")

def seed_baseline_cameras(cur):
    now = time.time()
    cameras = [
        ("CAM-01", "Main Gate", "Perimeter North Gate", "online", 25.0, "1080p", 38, 98.0, 0, None, 28.6139, 77.2090, "/api/cameras/CAM-01/stream", "/api/cameras/CAM-01/video", "/assets/cctv/cam01_real.jpg", json.dumps(["Perimeter", "Entry", "PTZ"]), 0, "backend/media/videos/cam01.mp4", 12.0, now),
        ("CAM-02", "Parking Area", "Sector B Parking Lot", "online", 25.0, "1080p", 44, 96.0, 0, None, 28.6145, 77.2105, "/api/cameras/CAM-02/stream", "/api/cameras/CAM-02/video", "/assets/cctv/cam02_real.jpg", json.dumps(["Parking", "Vehicles", "Outdoor"]), 0, "backend/media/videos/cam02.mp4", 14.0, now),
        ("CAM-03", "Corridor", "Administration Block Corridor", "online", 25.0, "1080p", 41, 96.0, 0, None, 28.6152, 77.2118, "/api/cameras/CAM-03/stream", "/api/cameras/CAM-03/video", "/assets/cctv/cam03_real.jpg", json.dumps(["Indoor", "Access Control"]), 0, "backend/media/videos/cam03.mp4", 18.0, now),
        ("CAM-04", "Exit Road", "Southern Arterial Exit", "online", 25.0, "1080p", 35, 99.0, 0, None, 28.6160, 77.2130, "/api/cameras/CAM-04/stream", "/api/cameras/CAM-04/video", "/assets/cctv/cam04_real.jpg", json.dumps(["Roadway", "Speed Gate"]), 0, "backend/media/videos/cam04.mp4", 16.0, now),
        ("CAM-05", "Junction", "Central Traffic Junction", "online", 24.0, "1080p", 46, 95.0, 0, None, 28.6130, 77.2110, "/api/cameras/CAM-05/stream", "/api/cameras/CAM-05/video", "/assets/cctv/cam05_real.jpg", json.dumps(["Traffic", "Panoramic"]), 0, "backend/media/videos/cam05.mp4", 20.0, now),
        ("CAM-06", "Warehouse", "Logistics & Storage Depot", "online", 25.0, "1080p", 40, 97.0, 0, None, 28.6168, 77.2095, "/api/cameras/CAM-06/stream", "/api/cameras/CAM-06/video", "/assets/cctv/cam06_real.jpg", json.dumps(["Storage", "Restricted Area"]), 0, "backend/media/videos/cam06.mp4", 25.0, now),
    ]
    cur.executemany("""
    INSERT INTO cameras (id, name, location, status, fps, resolution, latency_ms, trust_score, is_tampered, tamper_reason, lat, lng, stream_url, video_url, image_url, tags, is_uploaded, video_path, duration_sec, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, cameras)

def seed_demo_vehicles(cur):
    now = time.time()
    # Realistic test demonstration vehicle records
    vehicles = [
        ("DL01AB1234", "Rajesh Sharma", "Hyundai", "Creta 1.5 SX", "Motor Car (LMV)", "Polar White", "Diesel", "2022-04-12", "Delhi (DL-01 North)", "ACTIVE", 0, 1, now),
        ("MH12CD5678", "Vikramaditya Rao", "Toyota", "Innova Crysta 2.4Z", "Motor Car (LMV)", "Silver Metallic", "Diesel", "2021-08-19", "Maharashtra (MH-12 Pune)", "ACTIVE", 0, 1, now),
        ("UP16EF9012", "Arjun Patel", "Mahindra", "Scorpio-N Z8L", "Motor Car (LMV)", "Deep Forest Black", "Diesel", "2023-01-15", "Uttar Pradesh (UP-16 Noida)", "STOLEN", 1, 1, now),
        ("HR26GH3456", "Sandeep Varma", "Maruti Suzuki", "Brezza ZXi+", "Motor Car (LMV)", "Magma Grey", "Petrol", "2022-11-20", "Haryana (HR-26 Gurugram)", "ACTIVE", 0, 1, now),
        ("KA05JK7890", "Deepak Nambiar", "Tata", "Nexon EV Max", "Electric Car (LMV)", "Intensi-Teal", "Electric", "2023-06-05", "Karnataka (KA-05 Bangalore)", "ACTIVE", 0, 1, now),
        ("DL04XY4321", "Kunal Singhania", "Honda", "City 1.5 V-TEC", "Motor Car (LMV)", "Platinum White", "Petrol", "2020-03-10", "Delhi (DL-04 West)", "ACTIVE", 0, 1, now),
        ("CH01AA9999", "Harpreet Gill", "Mercedes-Benz", "E-Class E200", "Motor Car (LMV)", "Obsidian Black", "Petrol", "2023-09-01", "Chandigarh (CH-01)", "STOLEN", 1, 1, now),
    ]

    cur.executemany("""
    INSERT INTO vehicle_records (registration_number, owner_name, vehicle_make, vehicle_model, vehicle_class, color, fuel_type, registration_date, registration_state, status, is_stolen, is_demo_data, last_updated)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, vehicles)

    # Challans
    challans = [
        ("CHL-2026-001", "DL01AB1234", "DL-E-2026-88192", "2026-09-14 11:20:00", "Ring Road Near AIIMS", "Speed Violation (>80 km/h in 60 km/h zone)", 2000, "UNPAID", "CAM-04", "/assets/cctv/cam04_real.jpg", now),
        ("CHL-2026-002", "DL01AB1234", "DL-E-2026-99201", "2026-10-02 17:45:00", "Barakhamba Road Junction", "Red Light Jumping", 1000, "UNPAID", "CAM-05", "/assets/cctv/cam05_real.jpg", now),
        ("CHL-2026-003", "UP16EF9012", "UP-E-2026-34019", "2026-10-10 14:10:00", "Noida Expressway Toll", "Dangerous Driving / Lane Violation", 2500, "UNPAID", "CAM-01", "/assets/cctv/cam01_real.jpg", now),
        ("CHL-2026-004", "HR26GH3456", "HR-E-2026-11827", "2026-08-25 09:15:00", "Golf Course Road Crossing", "Unauthorized Parking in Tow Zone", 500, "PAID", "CAM-02", "/assets/cctv/cam02_real.jpg", now),
        ("CHL-2026-005", "CH01AA9999", "CH-E-2026-44021", "2026-10-18 22:30:00", "Sector 17 Inner Ring", "Reckless Driving & High Speed", 5000, "UNPAID", "CAM-04", "/assets/cctv/cam04_real.jpg", now),
    ]

    cur.executemany("""
    INSERT INTO challans (id, registration_number, challan_number, date_time, location, violation, penalty_amount, status, camera_id, evidence_url, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, challans)

    # Watchlist entries
    watchlist = [
        ("WCH-001", "UP16EF9012", "STOLEN", "CRITICAL", "Sector 58 Police Station / FIR #402/26", now, 1),
        ("WCH-002", "CH01AA9999", "STOLEN", "CRITICAL", "Central Crime Branch / FIR #911/26", now, 1),
        ("WCH-003", "DL01AB1234", "UNPAID_MULTIPLE_CHALLANS", "MEDIUM", "Traffic Enforcement Unit", now, 1),
    ]

    cur.executemany("""
    INSERT INTO watchlist (id, registration_number, reason, priority, listed_by, added_at, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, watchlist)

def seed_demo_detections_and_alerts(cur):
    now = time.time()
    
    # 1. Multi-camera journey for DL01AB1234
    detections = [
        ("PLT-DEMO-01", "CAM-01", "cam01.mp4", "VDET-01", 112, 4.5, "DL01AB1234", "DL 01 AB 1234", 0.94, "CAR", 0.96, "/assets/cctv/cam01_real.jpg", "matched", "verified", now - 3600),
        ("PLT-DEMO-02", "CAM-02", "cam02.mp4", "VDET-02", 562, 22.5, "DL01AB1234", "DL01AB1234", 0.91, "CAR", 0.94, "/assets/cctv/cam02_real.jpg", "matched", "verified", now - 3400),
        ("PLT-DEMO-03", "CAM-04", "cam04.mp4", "VDET-03", 975, 39.0, "DL01AB1234", "DL-01-AB-1234", 0.88, "CAR", 0.92, "/assets/cctv/cam04_real.jpg", "matched", "verified", now - 3200),
        
        # 2. Multi-camera journey for UP16EF9012 (STOLEN MATCH)
        ("PLT-DEMO-04", "CAM-07", "cam07.mp4", "VDET-04", 480, 16.0, "UP16EF9012", "UP 16 EF 9012", 0.95, "SUV", 0.97, "/assets/cctv/cam07_real.jpg", "matched", "verified", now - 1800),
        ("PLT-DEMO-05", "CAM-08", "cam08.mp4", "VDET-05", 1050, 35.0, "UP16EF9012", "UP16EF9012", 0.92, "SUV", 0.95, "/assets/cctv/cam08_real.jpg", "matched", "verified", now - 1600),
        ("PLT-DEMO-06", "CAM-09", "cam09.mp4", "VDET-06", 1440, 48.0, "UP16EF9012", "UP16EF9012", 0.89, "SUV", 0.93, "/assets/cctv/cam09_real.jpg", "matched", "verified", now - 1400),

        # 3. Detections for MH12CD5678 and CH01AA9999
        ("PLT-DEMO-07", "CAM-02", "cam02.mp4", "VDET-07", 275, 11.0, "MH12CD5678", "MH 12 CD 5678", 0.93, "CAR", 0.96, "/assets/cctv/cam02_real.jpg", "matched", "verified", now - 900),
        ("PLT-DEMO-08", "CAM-04", "cam04.mp4", "VDET-08", 350, 14.0, "CH01AA9999", "CH01AA9999", 0.96, "CAR", 0.98, "/assets/cctv/cam04_real.jpg", "matched", "verified", now - 600),
    ]

    cur.executemany("""
    INSERT OR IGNORE INTO plate_detections (
        id, camera_id, video_id, detection_id, frame_number, timestamp_sec,
        plate_number, raw_ocr_text, ocr_confidence, vehicle_class, vehicle_confidence,
        plate_crop_path, db_match_status, verification_status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, detections)

    # Initial Alerts for Stolen Vehicles
    alerts = [
        ("ALT-DEMO-01", "UP16EF9012", "PLT-DEMO-06", "CAM-09", 48.0, "STOLEN_VEHICLE_MATCH", "Potential stolen-vehicle record match — verification required", "Registration plate UP16EF9012 detected on CAM-09 (Boulevard Traffic Checkpoint). Matched against FIR #402/26 (Sector 58 PS). Verification required.", "/assets/cctv/cam09_real.jpg", "DEMO_WATCHLIST", 0.92, "ACTIVE", now - 1400, None, None, None),
        ("ALT-DEMO-02", "CH01AA9999", "PLT-DEMO-08", "CAM-04", 14.0, "STOLEN_VEHICLE_MATCH", "Potential stolen-vehicle record match — verification required", "Registration plate CH01AA9999 detected on CAM-04 (Exit Road). Matched against FIR #911/26 (Crime Branch). High priority alert.", "/assets/cctv/cam04_real.jpg", "DEMO_WATCHLIST", 0.96, "ACTIVE", now - 600, None, None, None),
        ("ALT-DEMO-03", "DL01AB1234", "PLT-DEMO-03", "CAM-04", 39.0, "CHALLAN_ACCUMULATION", "Multiple Unpaid Challans Detected (2 Violations)", "Vehicle DL01AB1234 has 2 unpaid e-challans totaling ₹3,000 for speed violation and red light jumping.", "/assets/cctv/cam04_real.jpg", "DEMO_WATCHLIST", 0.91, "ACKNOWLEDGED", now - 3200, "operator", now - 3000, "Operator reviewed violations list"),
    ]

    cur.executemany("""
    INSERT OR IGNORE INTO vehicle_alerts (
        id, registration_number, plate_detection_id, camera_id, timestamp_sec,
        alert_type, title, description, plate_crop_path, match_source, confidence,
        status, created_at, resolved_by, resolved_at, operator_notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts)

def seed_demo_object_searches(cur):
    now = time.time()
    searches = [
        (
            "SRCH-2026-001",
            "Red Tactical Backpack Investigation (OBJ-024)",
            "/assets/objects/red_backpack.jpg",
            "/assets/objects/red_backpack.jpg",
            "backpack",
            json.dumps([120, 180, 240, 320]),
            0.65,
            "active",
            json.dumps(["CAM-LIVE-01", "CAM-LIVE-02", "CAM-LIVE-03", "CAM-01", "CAM-02", "CAM-03"]),
            142,
            4,
            None,
            now - 7200,
            None
        ),
        (
            "SRCH-2026-002",
            "White Cargo Parcel Intake (OBJ-023)",
            "/assets/objects/white_package.jpg",
            "/assets/objects/white_package.jpg",
            "package",
            json.dumps([100, 150, 200, 260]),
            0.60,
            "active",
            json.dumps(["CAM-LIVE-01", "CAM-04", "CAM-06"]),
            88,
            2,
            None,
            now - 14400,
            None
        )
    ]

    cur.executemany("""
    INSERT OR IGNORE INTO object_searches (
        id, name, reference_image_path, reference_crop_path, target_class,
        roi_bbox_json, similarity_threshold, status, active_cameras_json,
        total_frames_searched, matches_count, error_message, created_at, stopped_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, searches)

    matches = [
        (
            "MATCH-2026-001",
            "SRCH-2026-001",
            "CAM-01",
            "Main Gate Entry",
            12.5,
            312,
            "backpack",
            0.92,
            0.88,
            json.dumps([420, 260, 95, 140]),
            "/assets/objects/red_backpack.jpg",
            "/assets/objects/red_backpack.jpg",
            "/assets/cctv/cam01_real.jpg",
            "/api/cameras/CAM-01/video",
            "confirmed",
            "Verified by Operator: High structural and color similarity to reference backpack.",
            "operator",
            now - 6800,
            now - 7100,
            12
        ),
        (
            "MATCH-2026-002",
            "SRCH-2026-001",
            "CAM-02",
            "Parking Area Sector B",
            28.0,
            700,
            "backpack",
            0.89,
            0.85,
            json.dumps([380, 290, 85, 130]),
            "/assets/objects/red_backpack.jpg",
            "/assets/objects/red_backpack.jpg",
            "/assets/cctv/cam02_real.jpg",
            "/api/cameras/CAM-02/video",
            "confirmed",
            "Subject carrying backpack across parking sector toward corridor.",
            "operator",
            now - 6400,
            now - 6700,
            8
        ),
        (
            "MATCH-2026-003",
            "SRCH-2026-001",
            "CAM-03",
            "Corridor Hallway",
            42.0,
            1050,
            "backpack",
            0.91,
            0.89,
            json.dumps([480, 310, 90, 135]),
            "/assets/objects/red_backpack.jpg",
            "/assets/objects/red_backpack.jpg",
            "/assets/cctv/cam03_real.jpg",
            "/api/cameras/CAM-03/video",
            "confirmed",
            "Backpack left unattended against wall corridor.",
            "operator",
            now - 6000,
            now - 6300,
            15
        ),
        (
            "MATCH-2026-004",
            "SRCH-2026-001",
            "CAM-LIVE-01",
            "Live Mobile Patrol Unit",
            5.2,
            78,
            "backpack",
            0.94,
            0.86,
            json.dumps([310, 240, 110, 160]),
            "/assets/objects/red_backpack.jpg",
            "/assets/objects/red_backpack.jpg",
            "/assets/cctv/camlive01_real.jpg",
            "/api/cameras/CAM-LIVE-01/stream",
            "unreviewed",
            "Live candidate match detected on mobile camera feed.",
            None,
            None,
            now - 120,
            5
        )
    ]

    cur.executemany("""
    INSERT OR IGNORE INTO object_matches (
        id, search_id, camera_id, camera_name, timestamp_sec, frame_number,
        object_class, detection_confidence, similarity_score, bbox_json,
        reference_crop_path, match_crop_path, frame_image_path, video_url,
        verification_status, operator_notes, verified_by, verified_at, created_at, observation_count
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, matches)

# Automatically initialize database when module is imported
init_db()
