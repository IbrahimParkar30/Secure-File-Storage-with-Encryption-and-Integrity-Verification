"""
app.py — Full Ethereum-integrated Flask application.
All file records stored on local Ganache Ethereum blockchain.
Smart contract (Solidity) enforces all upload/download rules.
"""

import hashlib
import os

from flask import (
    Flask, flash, jsonify, redirect,
    render_template, request, send_file, url_for,
)
from werkzeug.utils import secure_filename

from ethereum         import EthereumBlockchain
from encryption       import decrypt_file, encrypt_file
from security_monitor import SecurityMonitor, SecurityAlertLogger

UPLOAD_FOLDER    = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"
ALLOWED_EXTENSIONS = {
    "txt","pdf","png","jpg","jpeg","gif",
    "docx","xlsx","csv","zip","mp3","mp4",
}

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"),
)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-in-prod")

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Use Ethereum blockchain instead of custom blockchain.py
eth          = EthereumBlockchain()
monitor      = SecurityMonitor(eth)
alert_logger = monitor.logger


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def count_encrypted_files() -> int:
    return len([f for f in os.listdir(ENCRYPTED_FOLDER) if f.endswith(".enc")])


# ── Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    eth_status     = eth.get_status()
    unresolved     = alert_logger.get_unresolved()
    severity_count = alert_logger.count_by_severity()
    return render_template(
        "index.html",
        eth_status     = eth_status,
        unresolved     = unresolved,
        severity_count = severity_count,
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part in the request.", "danger")
        return redirect(url_for("index"))

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("index"))

    filename    = secure_filename(uploaded_file.filename)
    upload_path = os.path.join(UPLOAD_FOLDER, filename)
    enc_path    = os.path.join(ENCRYPTED_FOLDER, filename + ".enc")
    file_type   = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if not eth.is_connected():
        flash("Ethereum not connected. Start Ganache and run deploy.py.", "danger")
        return redirect(url_for("index"))

    uploaded_file.save(upload_path)
    file_size = os.path.getsize(upload_path)

    try:
        # Encrypt the file
        encrypt_file(upload_path, enc_path)
        file_hash = sha256_of_file(enc_path)
        os.remove(upload_path)

        # Register on Ethereum smart contract
        # Solidity require() statements enforce all rules automatically
        block = eth.add_block(
            file_name = filename,
            file_hash = file_hash,
            file_type = file_type,
            file_size = file_size,
        )

        return render_template(
            "upload_result.html",
            success   = True,
            filename  = filename,
            file_hash = file_hash,
            block     = block.to_dict(),
            ethereum  = True,
        )

    except ValueError as exc:
        # Solidity require() rejection
        for p in [upload_path, enc_path]:
            if os.path.exists(p): os.remove(p)
        error_msg = str(exc)
        # Clean up Solidity error prefix
        if "CONTRACT REJECTED" in error_msg:
            error_msg = error_msg.split("CONTRACT REJECTED:")[-1].strip()
            if "'" in error_msg:
                error_msg = error_msg.split("'")[1]
        return render_template(
            "upload_result.html",
            success          = False,
            filename         = filename,
            contract_result  = {"passed": False, "message": error_msg},
            contract_results = [],
            ethereum         = True,
        )

    except Exception as exc:
        for p in [upload_path, enc_path]:
            if os.path.exists(p): os.remove(p)
        flash(f"Upload failed: {exc}", "danger")
        return redirect(url_for("index"))


@app.route("/download", methods=["GET", "POST"])
def download():
    encrypted_files = [
        f.replace(".enc", "")
        for f in os.listdir(ENCRYPTED_FOLDER)
        if f.endswith(".enc")
    ]

    if request.method == "GET":
        return render_template("download.html", files=encrypted_files)

    filename = request.form.get("filename", "").strip()

    if not eth.is_connected():
        flash("Ethereum not connected. Start Ganache.", "danger")
        return redirect(url_for("download"))

    # Security Monitor — detect rename, alert, auto-heal
    security_result = monitor.verify_and_heal(filename)
    enc_path        = security_result["enc_path"]
    is_safe         = security_result["safe"]
    alert_obj       = security_result["alert_obj"]
    action_taken    = security_result["action_taken"]
    was_alerted     = security_result["alert"]

    block = eth.find_block_by_filename(filename)

    if not is_safe:
        alert_type  = alert_obj["alert_type"] if alert_obj else ""
        is_tampered = alert_type == "FILE_CONTENT_TAMPERED"
        stored_hash = block.file_hash if block else "N/A"
        computed_hash = sha256_of_file(enc_path) if (enc_path and os.path.exists(enc_path)) else "N/A"

        return render_template(
            "download_result.html",
            success       = False,
            error         = security_result["message"],
            filename      = filename,
            stored_hash   = stored_hash,
            computed_hash = computed_hash,
            tampered      = is_tampered,
            alert_obj     = alert_obj,
            action_taken  = action_taken,
            block         = block.to_dict() if block else None,
            contract_results = [],
            ethereum      = True,
        )

    # Compute hash for Ethereum verification
    current_hash = sha256_of_file(enc_path)

    # Call Solidity verifyIntegrity() — emits events on chain
    try:
        verify_result = eth.verify_integrity(filename, current_hash)
    except Exception as exc:
        verify_result = {"passed": False, "tx_hash": "", "error": str(exc)}

    if not verify_result["passed"]:
        is_tampered = (current_hash != block.file_hash) if block else False
        return render_template(
            "download_result.html",
            success       = False,
            error         = f"Smart contract integrity check failed. {verify_result.get('error','')}",
            filename      = filename,
            stored_hash   = block.file_hash if block else "N/A",
            computed_hash = current_hash,
            tampered      = is_tampered,
            alert_obj     = alert_obj,
            action_taken  = action_taken,
            block         = block.to_dict() if block else None,
            verify_tx     = verify_result.get("tx_hash",""),
            contract_results = [],
            ethereum      = True,
        )

    # All checks passed — decrypt and serve
    dec_path = os.path.join(DECRYPTED_FOLDER, filename)
    try:
        decrypt_file(enc_path, dec_path)
        if was_alerted and alert_obj:
            flash(f"⚠️ SECURITY ALERT: {alert_obj['description']}", "warning")
        return send_file(dec_path, as_attachment=True, download_name=filename)
    except Exception as exc:
        return render_template(
            "download_result.html",
            success  = False,
            error    = f"Decryption failed: {exc}",
            filename = filename,
            tampered = False,
        )


@app.route("/verify", methods=["GET", "POST"])
def verify():
    encrypted_files = [
        f.replace(".enc", "")
        for f in os.listdir(ENCRYPTED_FOLDER)
        if f.endswith(".enc")
    ]

    if request.method == "GET":
        return render_template("verify.html", files=encrypted_files)

    filename        = request.form.get("filename", "").strip()
    security_result = monitor.verify_and_heal(filename)
    enc_path        = security_result["enc_path"]
    is_safe         = security_result["safe"]
    alert_obj       = security_result["alert_obj"]
    action_taken    = security_result["action_taken"]

    block        = eth.find_block_by_filename(filename)
    current_hash = sha256_of_file(enc_path) if (enc_path and os.path.exists(enc_path)) else "N/A"
    is_tampered  = (block is not None and current_hash != "N/A" and current_hash != block.file_hash)

    verify_result = {"passed": False, "tx_hash": ""}
    if block and current_hash != "N/A" and eth.is_connected():
        try:
            verify_result = eth.verify_integrity(filename, current_hash)
        except Exception as exc:
            verify_result = {"passed": False, "tx_hash": "", "error": str(exc)}

    return render_template(
        "download_result.html",
        success          = is_safe and verify_result.get("passed", False),
        verify_only      = True,
        filename         = filename,
        stored_hash      = block.file_hash if block else "N/A",
        computed_hash    = current_hash,
        tampered         = is_tampered,
        chain_valid      = eth.is_chain_valid(),
        block            = block.to_dict() if block else None,
        alert_obj        = alert_obj,
        action_taken     = action_taken,
        verify_tx        = verify_result.get("tx_hash",""),
        contract_results = [],
        ethereum         = True,
        error            = None if (is_safe and verify_result.get("passed")) else security_result["message"],
    )


@app.route("/chain")
def chain_view():
    blocks      = eth.get_all_blocks()
    chain_valid = eth.is_chain_valid()
    events      = eth.get_recent_events(20)
    return render_template(
        "chain.html",
        blocks      = blocks,
        chain_valid = chain_valid,
        events      = events,
        ethereum    = True,
    )


@app.route("/ethereum")
def ethereum_status():
    """Ethereum network + contract status dashboard."""
    status = eth.get_status()
    events = eth.get_recent_events(30)
    return render_template(
        "ethereum_status.html",
        status = status,
        events = events,
    )


@app.route("/contracts")
def contracts_view():
    """Redirect old /contracts route to the Ethereum dashboard."""
    return redirect(url_for("ethereum_status"))


@app.route("/revoke", methods=["POST"])
def revoke_file():
    """Revoke a file via the smart contract."""
    filename = request.form.get("filename","").strip()
    try:
        tx_hash = eth.revoke_file(filename)
        flash(f"File '{filename}' access revoked. TX: {tx_hash[:20]}...", "warning")
    except Exception as exc:
        flash(f"Revoke failed: {exc}", "danger")
    return redirect(url_for("chain_view"))


@app.route("/alerts")
def alerts_view():
    alerts         = alert_logger.get_all()
    severity_count = alert_logger.count_by_severity()
    scan_results   = monitor.scan_all_files()
    return render_template(
        "alerts.html",
        alerts         = alerts,
        severity_count = severity_count,
        scan_results   = scan_results,
    )


@app.route("/alerts/scan")
def run_scan():
    scan_results = monitor.scan_all_files()
    for r in scan_results:
        if r["status"] == "TAMPERED":
            alert_logger.log(
                alert_type  = "SCAN_TAMPERED_FILE",
                severity    = "CRITICAL",
                description = f"Full scan detected tampered file: '{r['filename']}'",
                details     = r,
                resolved    = False,
            )
        elif r["status"] == "UNKNOWN":
            alert_logger.log(
                alert_type  = "SCAN_UNKNOWN_FILE",
                severity    = "MEDIUM",
                description = f"Full scan found unregistered file: '{r['filename']}'",
                details     = r,
                resolved    = False,
            )
    flash(f"Scan complete. {len(scan_results)} file(s) checked.", "info")
    return redirect(url_for("alerts_view"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
