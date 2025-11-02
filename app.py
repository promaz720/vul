from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from pathlib import Path
from datetime import datetime
import uuid
import os

from scanner import run_scans, ScanResult

app = Flask(__name__)
app.config["REPORT_DIR"] = Path("static/reports")
app.config["REPORT_DIR"].mkdir(parents=True, exist_ok=True)

# Cache for recent scans to avoid re-scanning same URLs
scan_cache = {}


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for Render"""
    return jsonify({"status": "healthy"}), 200


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        if not target_url:
            return render_template("index.html", error="Please provide a URL to scan.")

        scan_id = uuid.uuid4().hex
        report_path = app.config["REPORT_DIR"] / f"report_{scan_id}.html"

        # Use cache if available for same URL (within 5 minutes)
        if target_url in scan_cache:
            scan_result = scan_cache[target_url]
        else:
            scan_result = run_scans(target_url)
            scan_cache[target_url] = scan_result
            
        rendered_report = render_template(
            "report.html",
            target_url=target_url,
            scan_result=scan_result,
            scanned_at=datetime.utcnow(),
            report_id=scan_id,
        )
        report_path.write_text(rendered_report, encoding="utf-8")

        return render_template(
            "index.html",
            scan_result=scan_result,
            target_url=target_url,
            report_id=scan_id,
        )

    return render_template("index.html")


@app.route("/download/<report_id>")
def download_report(report_id: str):
    report_file = Path(f"static/reports/report_{report_id}.html")
    if not report_file.exists():
        return redirect(url_for("index"))
    return send_from_directory(
        directory=app.config["REPORT_DIR"],
        path=report_file.name,
        as_attachment=True,
    )


@app.route("/refresh", methods=["POST"])
def refresh_scan():
    """Clear the current scan results and return to fresh form"""
    return redirect(url_for("index"))


@app.route("/clear-cache", methods=["POST"])
def clear_cache():
    """Clear scan cache to allow fresh scans"""
    global scan_cache
    scan_cache.clear()
    return redirect(url_for("index"))


@app.context_processor
def inject_now():
    # Expose current UTC time to templates when needed.
    return {"now": datetime.utcnow()}


@app.errorhandler(500)
def internal_error(error):
    return render_template("error.html", error="Internal Server Error", code=500), 500


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", error="Page Not Found", code=404), 404


if __name__ == "__main__":
    # Get debug mode from environment, default to False for production
    debug_mode = os.getenv("FLASK_ENV") != "production"
    app.run(debug=debug_mode, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

