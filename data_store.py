import time
import hashlib
from typing import List, Dict, Optional
from backend.models.schemas import (
    Camera, Incident, TimelineEvent, TransitionEdge, PriorityFactor,
    IncidentReconstruction, SecurityCheck, SystemTrustResponse, AuditLogEntry, DemoStep
)

# In-Memory singleton datastore
class DataStore:
    def __init__(self):
        self.reset()

    def reset(self):
        self.cameras: Dict[str, Camera] = {
            "CAM-01": Camera(
                id="CAM-01",
                name="Main Gate",
                location="Perimeter North Gate",
                status="online",
                fps=25,
                resolution="1080p",
                latency_ms=38,
                trust_score=98.0,
                lat=28.6139,
                lng=77.2090,
                stream_url="/api/cameras/CAM-01/stream",
                video_url="/api/cameras/CAM-01/video",
                image_url="/assets/cctv/cam01_real.jpg",
                tags=["Perimeter", "Entry", "PTZ"]
            ),
            "CAM-02": Camera(
                id="CAM-02",
                name="Parking Area",
                location="Sector B Parking Lot",
                status="online",
                fps=25,
                resolution="1080p",
                latency_ms=44,
                trust_score=96.0,
                lat=28.6145,
                lng=77.2105,
                stream_url="/api/cameras/CAM-02/stream",
                video_url="/api/cameras/CAM-02/video",
                image_url="/assets/cctv/cam02_real.jpg",
                tags=["Parking", "Vehicles", "Outdoor"]
            ),
            "CAM-03": Camera(
                id="CAM-03",
                name="Corridor",
                location="Administration Block Corridor",
                status="online",
                fps=25,
                resolution="1080p",
                latency_ms=41,
                trust_score=96.0,  # Baseline normal
                lat=28.6152,
                lng=77.2118,
                stream_url="/api/cameras/CAM-03/stream",
                video_url="/api/cameras/CAM-03/video",
                image_url="/assets/cctv/cam03_real.jpg",
                tags=["Indoor", "Access Control"]
            ),
            "CAM-04": Camera(
                id="CAM-04",
                name="Exit Road",
                location="Southern Arterial Exit",
                status="online",
                fps=25,
                resolution="1080p",
                latency_ms=35,
                trust_score=99.0,
                lat=28.6160,
                lng=77.2130,
                stream_url="/api/cameras/CAM-04/stream",
                video_url="/api/cameras/CAM-04/video",
                image_url="/assets/cctv/cam04_real.jpg",
                tags=["Roadway", "Speed Gate"]
            ),
            "CAM-05": Camera(
                id="CAM-05",
                name="Junction",
                location="Central Traffic Junction",
                status="online",
                fps=24,
                resolution="1080p",
                latency_ms=46,
                trust_score=95.0,
                lat=28.6130,
                lng=77.2110,
                stream_url="/api/cameras/CAM-05/stream",
                video_url="/api/cameras/CAM-05/video",
                image_url="/assets/cctv/cam05_real.jpg",
                tags=["Traffic", "Panoramic"]
            ),
            "CAM-06": Camera(
                id="CAM-06",
                name="Warehouse",
                location="Logistics & Storage Depot",
                status="online",
                fps=25,
                resolution="1080p",
                latency_ms=40,
                trust_score=97.0,
                lat=28.6168,
                lng=77.2095,
                stream_url="/api/cameras/CAM-06/stream",
                video_url="/api/cameras/CAM-06/video",
                image_url="/assets/cctv/cam06_real.jpg",
                tags=["Storage", "Restricted Area"]
            )
        }

        self.incidents: Dict[str, Incident] = {
            "INC-2026-0142": Incident(
                id="INC-2026-0142",
                title="Multi-Camera Correlated Movement & Commotion",
                time="12:41 PM",
                timestamp=int(time.time()) - 1800,
                location="Main Gate → Parking → Corridor",
                cameras=["CAM-01", "CAM-02", "CAM-03", "CAM-04"],
                event_type="Unusual Movement",
                priority="HIGH",
                status="Requires Verification",
                confidence=0.91,
                description="Person P-104 entered via Main Gate, met Person P-118 in Parking sector, followed by rapid displacement into Corridor and left package on Exit Road.",
                tracked_entities=["P-104", "P-118"],
                requires_verification=True,
                compromised_feed=False,
                image_url="/assets/cctv/cam02_real.jpg",
                preview_sequence=["/assets/cctv/cam01_real.jpg", "/assets/cctv/cam02_real.jpg", "/assets/cctv/cam03_real.jpg", "/assets/cctv/cam04_real.jpg"]
            ),
            "INC-2026-0141": Incident(
                id="INC-2026-0141",
                title="Unattended Object at Transit Path",
                time="11:52 AM",
                timestamp=int(time.time()) - 4200,
                location="Exit Road Perimeter",
                cameras=["CAM-01", "CAM-05", "CAM-04"],
                event_type="Abandoned Object",
                priority="MEDIUM",
                status="Under Review",
                confidence=0.88,
                description="Stationary bag detected on sidewalk perimeter for > 180 seconds without proximate owner.",
                tracked_entities=["P-129", "OBJ-09"],
                requires_verification=True,
                compromised_feed=False,
                image_url="/assets/cctv/cam04_real.jpg",
                preview_sequence=["/assets/cctv/cam01_real.jpg", "/assets/cctv/cam05_real.jpg", "/assets/cctv/cam04_real.jpg"]
            ),
            "INC-2026-0140": Incident(
                id="INC-2026-0140",
                title="Vehicle Velocity Variation",
                time="10:31 AM",
                timestamp=int(time.time()) - 9600,
                location="Junction → Warehouse Depot",
                cameras=["CAM-05", "CAM-06"],
                event_type="Vehicle Anomaly",
                priority="LOW",
                status="Resolved",
                confidence=0.79,
                description="Vehicle V-021 executed abrupt lane deceleration near restricted gate entrance.",
                tracked_entities=["V-021"],
                requires_verification=False,
                compromised_feed=False,
                image_url="/assets/cctv/cam05_real.jpg",
                preview_sequence=["/assets/cctv/cam05_real.jpg", "/assets/cctv/cam06_real.jpg"]
            )
        }

        self.audit_logs: List[AuditLogEntry] = [
            AuditLogEntry(
                id="LOG-0941",
                timestamp="12:41:02",
                user="System Engine",
                action="Detection Triggered",
                target_entity="CAM-01 (Entity P-104)",
                system_module="DetectionEngine / YOLOv8",
                status="SUCCESS",
                hash_signature=self._gen_hash("12:41:02_P104_CAM01"),
                details="Person detected with 92% confidence score"
            ),
            AuditLogEntry(
                id="LOG-0942",
                timestamp="12:41:15",
                user="System Engine",
                action="Re-ID Match Correlated",
                target_entity="CAM-02 (Entity P-104)",
                system_module="ReIdEngine / OSNet",
                status="SUCCESS",
                hash_signature=self._gen_hash("12:41:15_ReID_CAM02"),
                details="Spatial-temporal correlation score: 0.91"
            ),
            AuditLogEntry(
                id="LOG-0943",
                timestamp="12:41:38",
                user="System Engine",
                action="Incident Synthesized",
                target_entity="INC-2026-0142",
                system_module="CorrelationEngine",
                status="SUCCESS",
                hash_signature=self._gen_hash("12:41:38_INC0142"),
                details="Generated multi-camera chronology across CAM-01, CAM-02, CAM-03"
            ),
            AuditLogEntry(
                id="LOG-0944",
                timestamp="12:43:11",
                user="Operator (operator_01)",
                action="Viewed Incident",
                target_entity="INC-2026-0142",
                system_module="Investigation Dashboard",
                status="SUCCESS",
                hash_signature=self._gen_hash("12:43:11_View_0142"),
                details="Operator reviewed unified incident timeline"
            ),
            AuditLogEntry(
                id="LOG-0945",
                timestamp="12:43:18",
                user="Cybersecurity Module",
                action="Integrity Verification Completed",
                target_entity="CAM-03",
                system_module="TrustEngine",
                status="VERIFIED",
                hash_signature=self._gen_hash("12:43:18_CAM03_Trust"),
                details="Frame checksum valid, RTP jitter 4.2ms"
            )
        ]

        self.is_cam3_tampered = False

    def _gen_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def add_audit_log(self, user: str, action: str, target: str, module: str, status: str, details: str = ""):
        entry = AuditLogEntry(
            id=f"LOG-{len(self.audit_logs) + 946:04d}",
            timestamp=time.strftime("%H:%M:%S"),
            user=user,
            action=action,
            target_entity=target,
            system_module=module,
            status=status,
            hash_signature=self._gen_hash(f"{time.time()}_{action}_{target}"),
            details=details
        )
        self.audit_logs.insert(0, entry)
        return entry

    def simulate_tamper(self, cam_id: str = "CAM-03"):
        if cam_id in self.cameras:
            cam = self.cameras[cam_id]
            cam.status = "tampered"
            cam.trust_score = 61.0
            cam.is_tampered = True
            cam.tamper_reason = "⚠ STREAM ANOMALY DETECTED | TIMESTAMP INCONSISTENCY (+42s) | FRAME LOOPING"
            self.is_cam3_tampered = True

            # Mark affected incident
            if "INC-2026-0142" in self.incidents:
                self.incidents["INC-2026-0142"].compromised_feed = True
                self.incidents["INC-2026-0142"].requires_verification = True

            self.add_audit_log(
                user="Cybersecurity Module",
                action="Tamper Simulation Triggered",
                target=f"{cam_id} Stream",
                module="TrustEngine",
                status="WARNING",
                details="Timestamp desynchronization (+42s) and looping packets detected. Trust score reduced to 61%."
            )

    def restore_camera(self, cam_id: str = "CAM-03"):
        if cam_id in self.cameras:
            cam = self.cameras[cam_id]
            cam.status = "online"
            cam.trust_score = 96.0
            cam.is_tampered = False
            cam.tamper_reason = None
            self.is_cam3_tampered = False

            # Restore incident
            if "INC-2026-0142" in self.incidents:
                self.incidents["INC-2026-0142"].compromised_feed = False

            self.add_audit_log(
                user="Cybersecurity Module",
                action="Camera Restored",
                target=f"{cam_id} Stream",
                module="TrustEngine",
                status="SUCCESS",
                details="Clock resynchronized with PTP server. Frame hashes verified. Camera trust restored to 96%."
            )

db = DataStore()
