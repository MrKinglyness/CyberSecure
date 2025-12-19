from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from models import db, Scan
from scan_logic import validate_scan_input, run_mock_scan

api_bp = Blueprint("api", __name__)

def get_user_scan(scan_id: int):
    return Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()

@api_bp.get("/api/scans")
@login_required
def api_list_scans():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    return jsonify([s.to_dict() for s in scans]), 200

@api_bp.post("/api/scans")
@login_required
def api_create_scan():
    data = request.get_json(silent=True) or {}
    scan_type = data.get("scan_type")
    target_value = data.get("target_value")
    findings_input = (data.get("findings") or "").strip()

    ok, err = validate_scan_input(scan_type, target_value)
    if not ok:
        return jsonify({"error": err}), 400

    status, findings_auto = run_mock_scan(scan_type, target_value)
    findings = findings_input if findings_input else findings_auto

    scan = Scan(
        user_id=current_user.id,
        scan_type=scan_type.strip().lower(),
        target_value=target_value.strip(),
        status=status,
        findings=findings,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(scan)
    db.session.commit()
    return jsonify(scan.to_dict()), 201

@api_bp.get("/api/scans/<int:scan_id>")
@login_required
def api_get_scan(scan_id: int):
    scan = get_user_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify(scan.to_dict()), 200

@api_bp.put("/api/scans/<int:scan_id>")
@login_required
def api_update_scan(scan_id: int):
    scan = get_user_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(silent=True) or {}

    scan_type = data.get("scan_type", scan.scan_type)
    target_value = data.get("target_value", scan.target_value)

    ok, err = validate_scan_input(scan_type, target_value)
    if not ok:
        return jsonify({"error": err}), 400

    status = (data.get("status") or scan.status).strip().lower()
    if status not in {"safe", "suspicious", "malicious"}:
        return jsonify({"error": "status must be safe suspicious or malicious"}), 400

    findings = (data.get("findings") if data.get("findings") is not None else scan.findings) or ""

    scan.scan_type = scan_type.strip().lower()
    scan.target_value = target_value.strip()
    scan.status = status
    scan.findings = findings.strip()
    scan.updated_at = datetime.utcnow()

    db.session.commit()
    return jsonify(scan.to_dict()), 200

@api_bp.delete("/api/scans/<int:scan_id>")
@login_required
def api_delete_scan(scan_id: int):
    scan = get_user_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    db.session.delete(scan)
    db.session.commit()
    return jsonify({"message": "deleted"}), 200
