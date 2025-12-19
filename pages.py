from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from models import db, Scan
from scan_logic import validate_scan_input, run_mock_scan

pages_bp = Blueprint("pages", __name__)

@pages_bp.get("/")
def home():
    return redirect(url_for("pages.dashboard"))

@pages_bp.get("/dashboard")
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    return render_template("dashboard.html", scans=scans)

@pages_bp.get("/scans/new")
@login_required
def new_scan_get():
    return render_template("new_scan.html")

@pages_bp.post("/scans/new")
@login_required
def new_scan_post():
    scan_type = (request.form.get("scan_type") or "").strip().lower()
    target_value = (request.form.get("target_value") or "").strip()
    findings_input = (request.form.get("findings") or "").strip()

    ok, err = validate_scan_input(scan_type, target_value)
    if not ok:
        flash(err)
        return redirect(url_for("pages.new_scan_get"))

    status, findings_auto = run_mock_scan(scan_type, target_value)
    findings = findings_input if findings_input else findings_auto

    scan = Scan(
        user_id=current_user.id,
        scan_type=scan_type,
        target_value=target_value,
        status=status,
        findings=findings
    )
    db.session.add(scan)
    db.session.commit()
    flash("Scan created")
    return redirect(url_for("pages.dashboard"))

@pages_bp.get("/scans/<int:scan_id>")
@login_required
def view_scan(scan_id: int):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        flash("Scan not found")
        return redirect(url_for("pages.dashboard"))
    return render_template("view_scan.html", scan=scan)

@pages_bp.get("/scans/<int:scan_id>/edit")
@login_required
def edit_scan_get(scan_id: int):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        flash("Scan not found")
        return redirect(url_for("pages.dashboard"))
    return render_template("edit_scan.html", scan=scan)

@pages_bp.post("/scans/<int:scan_id>/edit")
@login_required
def edit_scan_post(scan_id: int):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        flash("Scan not found")
        return redirect(url_for("pages.dashboard"))

    status = (request.form.get("status") or "").strip().lower()
    if status not in {"safe", "suspicious", "malicious"}:
        flash("Status must be safe suspicious or malicious")
        return redirect(url_for("pages.edit_scan_get", scan_id=scan_id))

    scan.status = status
    scan.findings = (request.form.get("findings") or "").strip()
    db.session.commit()
    flash("Scan updated")
    return redirect(url_for("pages.view_scan", scan_id=scan_id))

@pages_bp.post("/scans/<int:scan_id>/delete")
@login_required
def delete_scan(scan_id: int):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        flash("Scan not found")
        return redirect(url_for("pages.dashboard"))

    db.session.delete(scan)
    db.session.commit()
    flash("Scan deleted")
    return redirect(url_for("pages.dashboard"))
